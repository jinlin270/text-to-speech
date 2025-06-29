from flask import (
    Flask,
    request,
    Response,
    stream_with_context,
    render_template,
    jsonify,
    session,
)
import openai
from newspaper import Article
import time
import json
import uuid
from io import BytesIO
import os
import yaml
from pydub import AudioSegment
from flask_cors import CORS
import glob
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
CORS(app)  # allow cross-origin if frontend is hosted separately

# Store for past audio requests
audio_requests = {}

# Usage tracking
USAGE_LIMIT = float(os.getenv("USAGE_LIMIT", "10"))  # Configurable usage limit
current_usage = 0.0  # Track current usage in dollars

# Cost per character (in dollars)
COSTS = {
    "openai": 0.015 / 1000,  # $0.015 per 1K characters
    "polly": 0.004 / 1000,  # $0.004 per 1K characters
}

# Login attempt tracking (simple rate limiting)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT = 300  # 5 minutes

# def load_secrets(path="secrets.yml"):
#     with open(path, "r") as file:
#         secrets = yaml.safe_load(file)
#     return secrets
# secrets = load_secrets()
# openai.api_key = secrets["api-keys"]["open-api"]
openai.api_key = os.getenv("OPENAI_API_KEY")

# AWS Polly configuration
aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
aws_region = os.getenv("AWS_REGION", "us-east-1")

# Initialize AWS Polly client if credentials are available
polly_client = None
if aws_access_key_id and aws_secret_access_key:
    try:
        polly_client = boto3.client(
            "polly",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region,
        )
        print("[DEBUG] AWS Polly client initialized successfully")
    except Exception as e:
        print(f"[WARNING] Failed to initialize AWS Polly client: {e}")

os.makedirs("static", exist_ok=True)


def hash_password(password):
    """Hash password using SHA-256 with salt"""
    salt = os.getenv("PASSWORD_SALT", "default_salt_change_this")
    return hashlib.sha256((password + salt).encode()).hexdigest()


def check_login_attempts(ip):
    """Check if IP has exceeded login attempts"""
    global login_attempts
    current_time = time.time()

    # Clean up old attempts
    login_attempts = {
        ip: data
        for ip, data in login_attempts.items()
        if current_time - data["timestamp"] < LOGIN_TIMEOUT
    }

    if ip in login_attempts:
        attempts = login_attempts[ip]["count"]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            return False
    return True


def record_login_attempt(ip, success):
    """Record login attempt"""
    global login_attempts
    current_time = time.time()

    if ip not in login_attempts:
        login_attempts[ip] = {"count": 0, "timestamp": current_time}

    if not success:
        login_attempts[ip]["count"] += 1
        login_attempts[ip]["timestamp"] = current_time
    else:
        # Reset on successful login
        login_attempts.pop(ip, None)


def check_usage_limit(service, text_length):
    """Check if usage would exceed the $15 limit"""
    if session.get("authenticated_user") == "lin":
        return True  # Lin can bypass the limit

    cost = COSTS[service] * text_length
    if current_usage + cost > USAGE_LIMIT:
        return False
    return True


def calculate_cost(service, text_length):
    """Calculate cost for text synthesis"""
    return COSTS[service] * text_length


def update_usage(cost):
    """Update current usage"""
    global current_usage
    current_usage += cost
    print(f"[DEBUG] Usage updated: ${current_usage:.4f}")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/test", methods=["GET"])
def test():
    """Simple test endpoint"""
    return jsonify(
        {
            "status": "ok",
            "message": "Server is running",
            "lin_password_set": bool(os.getenv("LIN_PASSWORD")),
            "password_salt_set": bool(os.getenv("PASSWORD_SALT")),
        }
    )


@app.route("/api/usage", methods=["GET"])
def get_usage():
    """Get current usage information"""
    return jsonify(
        {
            "currentUsage": round(current_usage, 4),
            "usageLimit": USAGE_LIMIT,
            "remaining": round(USAGE_LIMIT - current_usage, 4),
            "isAuthenticated": session.get("authenticated_user") == "lin",
        }
    )


@app.route("/api/usage", methods=["POST"])
def update_usage():
    """Update usage limit (Lin only)"""
    if session.get("authenticated_user") != "lin":
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    action = data.get("action")

    global current_usage, USAGE_LIMIT

    if action == "reset":
        current_usage = 0.0
        return jsonify(
            {
                "success": True,
                "message": "Usage reset to $0.00",
                "currentUsage": 0.0,
                "usageLimit": USAGE_LIMIT,
            }
        )

    elif action == "set_limit":
        new_limit = data.get("limit")
        if (
            new_limit is None
            or not isinstance(new_limit, (int, float))
            or new_limit < 0
        ):
            return jsonify({"success": False, "message": "Invalid limit value"}), 400

        USAGE_LIMIT = float(new_limit)
        return jsonify(
            {
                "success": True,
                "message": f"Usage limit set to ${new_limit}",
                "currentUsage": current_usage,
                "usageLimit": USAGE_LIMIT,
            }
        )

    else:
        return jsonify({"success": False, "message": "Invalid action"}), 400


@app.route("/api/login", methods=["POST"])
def login():
    """Login endpoint for Lin"""
    try:
        print("[DEBUG] Login attempt received")

        # Get client IP for rate limiting
        client_ip = request.remote_addr
        print(f"[DEBUG] Client IP: {client_ip}")

        # Check rate limiting
        if not check_login_attempts(client_ip):
            print(f"[DEBUG] Rate limit exceeded for IP: {client_ip}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"Too many login attempts. Please wait {LOGIN_TIMEOUT//60} minutes.",
                    }
                ),
                429,
            )

        # Parse JSON data
        try:
            data = request.get_json()
            print(f"[DEBUG] Request data: {data}")
        except Exception as e:
            print(f"[ERROR] Failed to parse JSON: {e}")
            return jsonify({"success": False, "message": "Invalid JSON data"}), 400

        if not data:
            print("[DEBUG] No data provided")
            return jsonify({"success": False, "message": "No data provided"}), 400

        username = data.get("username")
        password = data.get("password")

        print(f"[DEBUG] Username: {username}")
        print(f"[DEBUG] Password provided: {'Yes' if password else 'No'}")

        if not username or not password:
            print("[DEBUG] Missing username or password")
            return (
                jsonify(
                    {"success": False, "message": "Username and password required"}
                ),
                400,
            )

        # Get password from environment variable
        lin_password = os.getenv("LIN_PASSWORD")
        if not lin_password:
            print("[WARNING] LIN_PASSWORD environment variable not set")
            return (
                jsonify({"success": False, "message": "Authentication not configured"}),
                500,
            )

        print(f"[DEBUG] Environment password set: {'Yes' if lin_password else 'No'}")

        # Hash the provided password
        hashed_password = hash_password(password)
        hashed_env_password = hash_password(lin_password)

        print(
            f"[DEBUG] Password hashes match: {hashed_password == hashed_env_password}"
        )

        # Check if it's Lin with correct password
        if username == "lin" and hashed_password == hashed_env_password:
            print("[DEBUG] Login successful")
            session["authenticated_user"] = "lin"
            session["login_time"] = time.time()
            record_login_attempt(client_ip, True)
            return jsonify({"success": True, "message": "Login successful"})
        else:
            print("[DEBUG] Login failed - invalid credentials")
            record_login_attempt(client_ip, False)
            return jsonify({"success": False, "message": "Invalid credentials"}), 401

    except Exception as e:
        print(f"[ERROR] Login error: {e}")
        import traceback

        traceback.print_exc()
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/api/logout", methods=["POST"])
def logout():
    """Logout endpoint"""
    session.clear()
    return jsonify({"success": True, "message": "Logout successful"})


@app.route("/api/requests", methods=["GET"])
def get_requests():
    """Get all past audio requests"""
    requests_list = []
    for session_id, request_data in audio_requests.items():
        requests_list.append(
            {
                "sessionId": session_id,
                "url": request_data["url"],
                "voice": request_data["voice"],
                "service": request_data["service"],
                "timestamp": request_data["timestamp"],
                "totalChunks": request_data["totalChunks"],
                "totalDuration": request_data["totalDuration"],
                "cost": request_data.get("cost", 0),
                "combinedAudioUrl": f"/static/combined_{session_id}.mp3",
            }
        )

    # Sort by timestamp (newest first)
    requests_list.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(requests_list)


def chunk_text(text, max_chars=500):
    # Split on paragraph boundaries if possible
    paragraphs = text.split("\n")
    chunks, chunk = [], ""
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue  # skip empty paragraphs
        if len(chunk) + len(para) < max_chars:
            chunk += para + "\n"
        else:
            if chunk.strip():  # only append non-empty chunk
                chunks.append(chunk.strip())
            chunk = para + "\n"
    if chunk.strip():
        chunks.append(chunk.strip())
    return chunks


def combine_audio_chunks(chunk_files, output_path):
    combined = AudioSegment.empty()
    for file in chunk_files:
        audio_segment = AudioSegment.from_file(file, format="mp3")
        combined += audio_segment
    combined.export(output_path, format="mp3")


def cleanup_old_audio_files():
    """Remove audio files older than 1 hour to prevent disk space issues"""
    try:
        current_time = time.time()
        audio_files = glob.glob("static/*.mp3")

        for file_path in audio_files:
            file_age = current_time - os.path.getmtime(file_path)
            # Remove files older than 1 hour (3600 seconds)
            if file_age > 3600:
                os.remove(file_path)
                print(f"[DEBUG] Cleaned up old audio file: {file_path}")
    except Exception as e:
        print(f"[WARNING] Error during cleanup: {e}")


def synthesize_with_openai(text, voice):
    """Synthesize speech using OpenAI TTS"""
    try:
        response = openai.audio.speech.create(model="tts-1", voice=voice, input=text)
        return response.content
    except Exception as e:
        print(f"[ERROR] OpenAI TTS failed: {e}")
        raise


def synthesize_with_polly(text, voice):
    """Synthesize speech using AWS Polly"""
    if not polly_client:
        raise Exception("AWS Polly client not initialized")

    try:
        # Map frontend voice names to Polly voice IDs
        voice_mapping = {
            "joanna": "Joanna",
            "matthew": "Matthew",
            "ivy": "Ivy",
            "justin": "Justin",
            "kendra": "Kendra",
            "kevin": "Kevin",
            "salli": "Salli",
            "kimberly": "Kimberly",
            "joey": "Joey",
            "emma": "Emma",
        }

        polly_voice = voice_mapping.get(voice, "Joanna")

        response = polly_client.synthesize_speech(
            Text=text,
            OutputFormat="mp3",
            VoiceId=polly_voice,
            Engine="neural",  # Use neural engine for better quality
        )

        return response["AudioStream"].read()
    except ClientError as e:
        print(f"[ERROR] AWS Polly TTS failed: {e}")
        raise Exception(f"AWS Polly error: {e}")
    except Exception as e:
        print(f"[ERROR] AWS Polly TTS failed: {e}")
        raise


@app.route("/stream-read", methods=["GET"])
def stream_read():
    url = request.args.get("url")
    voice = request.args.get("voice", "shimmer")
    service = request.args.get("service", "openai")  # "openai" or "polly"

    print("[DEBUG] Received request for URL:", url)
    print("[DEBUG] Selected voice:", voice)
    print("[DEBUG] Selected service:", service)

    if not url:
        print("[ERROR] No URL provided")
        return Response("No URL provided", status=400)

    # Validate service selection
    if service not in ["openai", "polly"]:
        print("[ERROR] Invalid service selected")
        return Response("Invalid service selected", status=400)

    # Check if service is available
    if service == "openai" and not openai.api_key:
        print("[ERROR] OpenAI API key not configured")
        return Response("OpenAI service not configured", status=500)

    if service == "polly" and not polly_client:
        print("[ERROR] AWS Polly not configured")
        return Response("AWS Polly service not configured", status=500)

    # Clean up old files before starting
    cleanup_old_audio_files()

    def generate(voice, service):
        chunk_files = []
        session_id = uuid.uuid4().hex
        combined_audio_path = f"static/combined_{session_id}.mp3"
        total_cost = 0.0

        try:
            print("[DEBUG] Starting article parsing...")
            article = Article(url)
            article.download()
            article.parse()
            text = article.text
            print("[DEBUG] Article downloaded and parsed, text length:", len(text))

            chunks = chunk_text(text)
            print(f"[DEBUG] Text split into {len(chunks)} chunk(s).")

            # Check usage limit before processing
            total_text_length = sum(len(chunk) for chunk in chunks)
            estimated_cost = calculate_cost(service, total_text_length)

            if not check_usage_limit(service, total_text_length):
                error_msg = f"Usage limit exceeded. Estimated cost: ${estimated_cost:.4f}, Remaining: ${USAGE_LIMIT - current_usage:.4f}"
                print(f"[ERROR] {error_msg}")
                yield f"event: error\ndata: {json.dumps({'error': error_msg})}\n\n"
                return

            # Initialize request data
            audio_requests[session_id] = {
                "url": url,
                "voice": voice,
                "service": service,
                "timestamp": datetime.now().isoformat(),
                "totalChunks": 0,
                "totalDuration": 0,
                "cost": 0.0,
            }

            # Validate voice based on service
            if service == "openai":
                allowed_voices = {"shimmer", "onyx", "nova", "echo", "fable"}
                if voice not in allowed_voices:
                    print(
                        f"[WARNING] Invalid OpenAI voice '{voice}', defaulting to shimmer."
                    )
                    voice = "shimmer"
            elif service == "polly":
                allowed_voices = {
                    "joanna",
                    "matthew",
                    "ivy",
                    "justin",
                    "kendra",
                    "kevin",
                    "salli",
                    "kimberly",
                    "joey",
                    "emma",
                }
                if voice not in allowed_voices:
                    print(
                        f"[WARNING] Invalid Polly voice '{voice}', defaulting to joanna."
                    )
                    voice = "joanna"

            for idx, chunk in enumerate(chunks):
                print(
                    f"[DEBUG] Synthesizing chunk {idx + 1}/{len(chunks)} with {service}..."
                )

                # Calculate cost for this chunk
                chunk_cost = calculate_cost(service, len(chunk))
                total_cost += chunk_cost

                # Synthesize speech based on selected service
                if service == "openai":
                    audio_bytes = synthesize_with_openai(chunk, voice)
                else:  # polly
                    audio_bytes = synthesize_with_polly(chunk, voice)

                print("[DEBUG] TTS request complete, saving audio...")
                audio_segment = AudioSegment.from_file(
                    BytesIO(audio_bytes), format="mp3"
                )
                duration_sec = audio_segment.duration_seconds

                # Save individual chunk to file
                chunk_filename = f"static/chunk_{session_id}_{idx}.mp3"
                with open(chunk_filename, "wb") as f:
                    f.write(audio_bytes)

                chunk_files.append(chunk_filename)

                # Calculate total duration so far
                total_duration_so_far = sum(
                    AudioSegment.from_file(f, format="mp3").duration_seconds
                    for f in chunk_files
                )

                print(f"[DEBUG] Audio saved as {chunk_filename}")

                # Send individual chunk URL and metadata to frontend
                data = {
                    "audioUrl": "/" + chunk_filename,
                    "chunkDuration": duration_sec,
                    "totalDuration": total_duration_so_far,
                    "chunkIndex": idx,
                    "totalChunks": len(chunks),
                    "sessionId": session_id,
                }
                yield f"data: {json.dumps(data)}\n\n"

                # Short delay to pace the stream
                time.sleep(0.5)

            # Create combined audio file when streaming is complete
            print("[DEBUG] Creating combined audio file...")
            combine_audio_chunks(chunk_files, combined_audio_path)
            print(f"[DEBUG] Combined audio saved as {combined_audio_path}")

            # Remove individual chunk files to save disk space
            print("[DEBUG] Cleaning up individual chunk files...")
            for chunk_file in chunk_files:
                try:
                    os.remove(chunk_file)
                    print(f"[DEBUG] Removed chunk file: {chunk_file}")
                except Exception as e:
                    print(f"[WARNING] Failed to remove chunk file {chunk_file}: {e}")

            # Update usage and request data
            update_usage(total_cost)
            audio_requests[session_id]["totalChunks"] = len(chunks)
            audio_requests[session_id]["totalDuration"] = total_duration_so_far
            audio_requests[session_id]["cost"] = total_cost

            print(f"[DEBUG] Total cost for this request: ${total_cost:.4f}")
            print("[DEBUG] Streaming complete.")
            yield "event: end\ndata: {}\n\n"

        except Exception as e:
            print("[ERROR] Exception occurred:", str(e))
            import traceback

            traceback.print_exc()

            error_data = {"error": str(e)}
            yield f"event: error\ndata: {json.dumps(error_data)}\n\n"

    return Response(
        stream_with_context(generate(voice, service)), mimetype="text/event-stream"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))  # Use Render's PORT if available
    app.run(host="0.0.0.0", port=port, debug=True)
