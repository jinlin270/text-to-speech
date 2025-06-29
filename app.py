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
import PyPDF2
import base64

openai.api_key = os.getenv("OPENAI_API_KEY")
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
CORS(app)  # allow cross-origin if frontend is hosted separately

# Debug session configuration
print(f"[DEBUG] Flask secret key set: {bool(app.secret_key)}")
print(f"[DEBUG] Secret key length: {len(app.secret_key) if app.secret_key else 0}")

# Store for past audio requests
audio_requests = {}

# Store for PDF text files (session_id -> file_path)
pdf_text_files = {}

# Track active streaming sessions for stop functionality
active_streaming_sessions = {}

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
            "openai_configured": bool(openai.api_key),
            "aws_polly_configured": bool(polly_client),
            "aws_credentials_set": bool(aws_access_key_id and aws_secret_access_key),
            "aws_region": aws_region,
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
def update_usage_limit():
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
                "status": request_data.get("status", "unknown"),
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
        print(f"[DEBUG] AWS Polly: Using voice '{voice}' for text length {len(text)}")

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
        print(f"[DEBUG] AWS Polly: Mapped voice '{voice}' to '{polly_voice}'")

        # Check if text is too long for Polly (6000 characters limit)
        if len(text) > 6000:
            print(
                f"[WARNING] Text too long for Polly ({len(text)} chars), truncating to 6000"
            )
            text = text[:6000]

        response = polly_client.synthesize_speech(
            Text=text,
            OutputFormat="mp3",
            VoiceId=polly_voice,
            Engine="neural",  # Use neural engine for better quality
        )

        audio_data = response["AudioStream"].read()
        print(f"[DEBUG] AWS Polly: Successfully synthesized {len(audio_data)} bytes")
        return audio_data

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        print(f"[ERROR] AWS Polly ClientError: {error_code} - {error_message}")

        if error_code == "InvalidParameterValue":
            raise Exception(f"Invalid voice or text parameter: {error_message}")
        elif error_code == "TextLengthExceededException":
            raise Exception(f"Text too long for AWS Polly: {error_message}")
        elif error_code == "UnsupportedPlsAlphabetException":
            raise Exception(f"Unsupported text format: {error_message}")
        else:
            raise Exception(f"AWS Polly error ({error_code}): {error_message}")

    except Exception as e:
        print(f"[ERROR] AWS Polly TTS failed: {e}")
        raise Exception(f"AWS Polly error: {str(e)}")


def validate_streaming_request(service, source_type="url"):
    """Validate streaming request parameters and service availability

    Args:
        service (str): TTS service to use ("openai" or "polly")
        source_type (str): Type of source ("url" or "pdf")

    Raises:
        ValueError: If service is invalid or not configured
    """
    if service not in ["openai", "polly"]:
        raise ValueError("Invalid service selected")

    if service == "openai" and not openai.api_key:
        raise ValueError("OpenAI service not configured")

    if service == "polly":
        if not polly_client:
            raise ValueError(
                "AWS Polly service not configured. Please check AWS credentials."
            )
        if not aws_access_key_id or not aws_secret_access_key:
            raise ValueError(
                "AWS credentials not configured. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
            )


def get_text_from_source(source_type, url=None):
    """Extract text from URL or PDF based on source type

    Args:
        source_type (str): Type of source ("url" or "pdf")
        url (str, optional): URL to extract text from (for URL source type)

    Returns:
        tuple: (extracted_text, source_identifier)

    Raises:
        ValueError: If source is invalid or text extraction fails
    """
    if source_type == "url":
        if not url:
            raise ValueError("No URL provided")

        # Add retry logic for article download
        max_retries = 3
        retry_delay = 2  # seconds

        for attempt in range(max_retries):
            try:
                article = Article(url)
                article.download()
                article.parse()
                break  # Success, exit retry loop
            except Exception as e:
                if "429" in str(e) or "Too Many Requests" in str(e):
                    if attempt < max_retries - 1:
                        print(
                            f"[WARNING] Rate limited (attempt {attempt + 1}/{max_retries}). Waiting {retry_delay} seconds..."
                        )
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        print("[ERROR] Rate limited after all retries")
                        raise ValueError(
                            "Website is rate limiting requests. Please try again later or use a different URL."
                        )
                else:
                    # Non-rate-limit error, don't retry
                    raise e

        text = article.text
        if not text or len(text.strip()) < 10:
            raise ValueError(
                "No readable text content found on this page. Please try a different URL."
            )

        return text, url

    elif source_type == "pdf":
        pdf_session_id = session.get("pdf_session_id")
        pdf_filename = session.get("pdf_filename")

        if not pdf_session_id:
            raise ValueError("No PDF session found. Please upload a PDF first.")

        # Get the text file path
        pdf_text_file = pdf_text_files.get(pdf_session_id)
        if not pdf_text_file:
            raise ValueError("PDF text file not found. Please upload a PDF first.")

        # Read the text from file
        try:
            with open(pdf_text_file, "r", encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            raise ValueError("PDF text file not found. Please upload a PDF first.")
        except Exception as e:
            raise ValueError(f"Failed to read PDF text: {str(e)}")

        if not text or len(text.strip()) < 10:
            raise ValueError(
                "No readable text found in PDF. Please try a different PDF."
            )

        return text, f"PDF: {pdf_filename}"

    else:
        raise ValueError(f"Invalid source type: {source_type}")


def validate_voice_for_service(voice, service):
    """Validate and return appropriate voice for the selected service

    Args:
        voice (str): Requested voice name
        service (str): TTS service ("openai" or "polly")

    Returns:
        str: Validated voice name (defaults to service default if invalid)
    """
    if service == "openai":
        allowed_voices = {"shimmer", "onyx", "nova", "echo", "fable"}
        if voice not in allowed_voices:
            print(f"[WARNING] Invalid OpenAI voice '{voice}', defaulting to shimmer.")
            return "shimmer"
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
            print(f"[WARNING] Invalid Polly voice '{voice}', defaulting to joanna.")
            return "joanna"

    return voice


def check_usage_and_initialize_request(text, service, voice, source_type):
    """Check usage limits and initialize request data

    Args:
        text (str): Text to be processed
        service (str): TTS service to use
        voice (str): Voice to use
        source_type (str): Source identifier for the request

    Returns:
        tuple: (text_chunks, session_id)

    Raises:
        ValueError: If usage limit would be exceeded
    """
    chunks = chunk_text(text)
    print(f"[DEBUG] Text split into {len(chunks)} chunk(s).")

    # Check usage limit before processing
    total_text_length = sum(len(chunk) for chunk in chunks)
    estimated_cost = calculate_cost(service, total_text_length)

    if not check_usage_limit(service, total_text_length):
        error_msg = f"Usage limit exceeded. Estimated cost: ${estimated_cost:.4f}, Remaining: ${USAGE_LIMIT - current_usage:.4f}"
        print(f"[ERROR] {error_msg}")
        raise ValueError(error_msg)

    # Initialize request data
    session_id = uuid.uuid4().hex
    audio_requests[session_id] = {
        "url": source_type,
        "voice": voice,
        "service": service,
        "timestamp": datetime.now().isoformat(),
        "totalChunks": 0,
        "totalDuration": 0,
        "cost": 0.0,
        "status": "processing",
        "source_type": source_type,
    }

    return chunks, session_id


def finalize_audio_request(chunk_files, session_id, total_cost, total_duration_so_far):
    """Create combined audio file and clean up temporary files

    Args:
        chunk_files (list): List of chunk file paths
        session_id (str): Unique session identifier
        total_cost (float): Total cost of the request
        total_duration_so_far (float): Total duration of all chunks
    """
    combined_audio_path = f"static/combined_{session_id}.mp3"

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
    audio_requests[session_id]["totalChunks"] = len(chunk_files)
    audio_requests[session_id]["totalDuration"] = total_duration_so_far
    audio_requests[session_id]["cost"] = total_cost
    audio_requests[session_id]["status"] = "completed"

    print(f"[DEBUG] Total cost for this request: ${total_cost:.4f}")
    print("[DEBUG] Streaming complete.")


def generate_streaming_audio(source_type, voice, service, url=None):
    """Main streaming generator function that handles both URL and PDF sources

    Args:
        source_type (str): Type of source ("url" or "pdf")
        voice (str): Voice to use for TTS
        service (str): TTS service to use ("openai" or "polly")
        url (str, optional): URL to process (for URL source type)

    Yields:
        str: Server-sent events data for streaming audio chunks
    """
    session_id = None
    try:
        # Validate request
        validate_streaming_request(service, source_type)

        # Get text from source
        text, source_url = get_text_from_source(source_type, url)
        print(f"[DEBUG] {source_type.upper()} text length: {len(text)}")

        # Validate and normalize voice
        voice = validate_voice_for_service(voice, service)

        # Check usage and initialize request
        chunks, session_id = check_usage_and_initialize_request(
            text, service, voice, source_type
        )
        # Store the actual url for reference
        audio_requests[session_id]["url"] = source_url

        # Register this session for stop functionality
        active_streaming_sessions[session_id] = {
            "stop_requested": False,
            "created_time": time.time(),
        }
        print(f"[DEBUG] Session {session_id} registered for streaming")

        # Clean up old sessions periodically
        cleanup_old_sessions()

        # Process audio chunks and yield streaming data
        chunk_files = []
        total_cost = 0.0

        try:
            for idx, chunk in enumerate(chunks):
                # Check if this session should be stopped
                if should_stop_session(session_id):
                    print(
                        f"[DEBUG] Session {session_id} stop requested, terminating streaming"
                    )

                    # Save partial results if we have any chunks
                    if chunk_files:
                        print(
                            f"[DEBUG] Saving partial results: {len(chunk_files)} chunks generated"
                        )
                        partial_cost = sum(
                            calculate_cost(service, len(chunks[i]))
                            for i in range(len(chunk_files))
                        )
                        partial_duration = sum(
                            AudioSegment.from_file(f, format="mp3").duration_seconds
                            for f in chunk_files
                        )

                        # Create combined audio from partial chunks
                        combined_audio_path = f"static/combined_{session_id}.mp3"
                        combine_audio_chunks(chunk_files, combined_audio_path)

                        # Update usage and request data for partial completion
                        update_usage(partial_cost)
                        audio_requests[session_id]["totalChunks"] = len(chunk_files)
                        audio_requests[session_id]["totalDuration"] = partial_duration
                        audio_requests[session_id]["cost"] = partial_cost
                        audio_requests[session_id]["status"] = "stopped"

                        print(
                            f"[DEBUG] Partial completion saved: {len(chunk_files)} chunks, ${partial_cost:.4f} cost"
                        )

                    yield f"event: stop\ndata: {json.dumps({'message': 'Streaming stopped by user request', 'partialChunks': len(chunk_files)})}\n\n"
                    return

                print(
                    f"[DEBUG] Synthesizing chunk {idx + 1}/{len(chunks)} with {service}..."
                )

                # Calculate cost for this chunk
                chunk_cost = calculate_cost(service, len(chunk))
                total_cost += chunk_cost

                # Synthesize speech based on selected service
                try:
                    if service == "openai":
                        audio_bytes = synthesize_with_openai(chunk, voice)
                    else:  # polly
                        audio_bytes = synthesize_with_polly(chunk, voice)
                except Exception as e:
                    print(f"[ERROR] TTS synthesis failed for chunk {idx + 1}: {e}")
                    raise Exception(f"TTS synthesis failed: {str(e)}")

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

            # Finalize the request
            finalize_audio_request(
                chunk_files, session_id, total_cost, total_duration_so_far
            )

            yield "event: end\ndata: {}\n\n"

        except GeneratorExit:
            # Client disconnected unexpectedly, save partial results
            print(
                f"[DEBUG] Client disconnected for session {session_id}, saving partial results"
            )
            if chunk_files:
                partial_cost = sum(
                    calculate_cost(service, len(chunks[i]))
                    for i in range(len(chunk_files))
                )
                partial_duration = sum(
                    AudioSegment.from_file(f, format="mp3").duration_seconds
                    for f in chunk_files
                )

                # Create combined audio from partial chunks
                combined_audio_path = f"static/combined_{session_id}.mp3"
                combine_audio_chunks(chunk_files, combined_audio_path)

                # Update usage and request data for partial completion
                update_usage(partial_cost)
                audio_requests[session_id]["totalChunks"] = len(chunk_files)
                audio_requests[session_id]["totalDuration"] = partial_duration
                audio_requests[session_id]["cost"] = partial_cost
                audio_requests[session_id]["status"] = "disconnected"

                print(
                    f"[DEBUG] Partial completion saved after disconnect: {len(chunk_files)} chunks, ${partial_cost:.4f} cost"
                )
            raise  # Re-raise to ensure proper cleanup

    except Exception as e:
        print("[ERROR] Exception occurred:", str(e))
        import traceback

        traceback.print_exc()
        error_data = {"error": str(e)}
        yield f"event: error\ndata: {json.dumps(error_data)}\n\n"
    finally:
        # Always clean up the session
        if session_id:
            cleanup_session(session_id)


@app.route("/stream-read", methods=["GET"])
def stream_read():
    url = request.args.get("url")
    voice = request.args.get("voice", "shimmer")
    service = request.args.get("service", "openai")

    print("[DEBUG] Received request for URL:", url)
    print("[DEBUG] Selected voice:", voice)
    print("[DEBUG] Selected service:", service)

    if not url:
        print("[ERROR] No URL provided")
        return Response("No URL provided", status=400)

    # Clean up old files before starting
    cleanup_old_audio_files()

    return Response(
        stream_with_context(generate_streaming_audio("url", voice, service, url)),
        mimetype="text/event-stream",
    )


@app.route("/stream-pdf", methods=["GET"])
def stream_pdf():
    voice = request.args.get("voice", "shimmer")
    service = request.args.get("service", "openai")

    print("[DEBUG] Received PDF streaming request")
    print("[DEBUG] Selected voice:", voice)
    print("[DEBUG] Selected service:", service)
    print(f"[DEBUG] Session ID: {session.get('_id', 'No session ID')}")
    print(f"[DEBUG] Session keys: {list(session.keys())}")
    print(f"[DEBUG] Session contains pdf_text: {'pdf_text' in session}")
    print(f"[DEBUG] Session contains pdf_filename: {'pdf_filename' in session}")

    # Clean up old files before starting
    cleanup_old_audio_files()

    return Response(
        stream_with_context(generate_streaming_audio("pdf", voice, service)),
        mimetype="text/event-stream",
    )


@app.route("/api/upload-pdf", methods=["POST"])
def upload_pdf():
    """Handle PDF upload and extract text"""
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "message": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"success": False, "message": "No file selected"}), 400

        if not file.filename.lower().endswith(".pdf"):
            return jsonify({"success": False, "message": "File must be a PDF"}), 400

        # Read PDF content
        pdf_content = file.read()

        # Extract text from PDF
        text = extract_text_from_pdf(pdf_content)

        if not text or len(text.strip()) < 10:
            return (
                jsonify({"success": False, "message": "No readable text found in PDF"}),
                400,
            )

        # Generate a unique session ID for this PDF
        pdf_session_id = uuid.uuid4().hex

        # Store the extracted text in a temporary file
        pdf_text_file = f"static/pdf_text_{pdf_session_id}.txt"
        with open(pdf_text_file, "w", encoding="utf-8") as f:
            f.write(text)

        # Store the file path and filename in session (small data)
        session["pdf_session_id"] = pdf_session_id
        session["pdf_filename"] = file.filename

        # Store the mapping in memory
        pdf_text_files[pdf_session_id] = pdf_text_file

        print(f"[DEBUG] PDF uploaded successfully:")
        print(f"[DEBUG] - Filename: {file.filename}")
        print(f"[DEBUG] - Text length: {len(text)}")
        print(f"[DEBUG] - PDF Session ID: {pdf_session_id}")
        print(f"[DEBUG] - Text file: {pdf_text_file}")
        print(
            f"[DEBUG] - Session contains pdf_session_id: {'pdf_session_id' in session}"
        )
        print(f"[DEBUG] - Session contains pdf_filename: {'pdf_filename' in session}")

        return jsonify(
            {
                "success": True,
                "message": f"PDF processed successfully. Extracted {len(text)} characters.",
                "textLength": len(text),
                "filename": file.filename,
                "pdfSessionId": pdf_session_id,
            }
        )

    except Exception as e:
        print(f"[ERROR] PDF upload failed: {e}")
        return (
            jsonify({"success": False, "message": f"PDF processing failed: {str(e)}"}),
            500,
        )


def extract_text_from_pdf(pdf_content):
    """Extract text from PDF content"""
    try:
        pdf_file = BytesIO(pdf_content)
        pdf_reader = PyPDF2.PdfReader(pdf_file)

        text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text += page.extract_text() + "\n"

        return text.strip()

    except Exception as e:
        print(f"[ERROR] PDF text extraction failed: {e}")
        raise Exception(f"Failed to extract text from PDF: {str(e)}")


@app.route("/api/clear-pdf", methods=["POST"])
def clear_pdf():
    """Clear PDF data from session and remove temporary files"""
    try:
        # Get the PDF session ID
        pdf_session_id = session.get("pdf_session_id")

        if pdf_session_id:
            # Remove the text file
            pdf_text_file = pdf_text_files.get(pdf_session_id)
            if pdf_text_file and os.path.exists(pdf_text_file):
                try:
                    os.remove(pdf_text_file)
                    print(f"[DEBUG] Removed PDF text file: {pdf_text_file}")
                except Exception as e:
                    print(
                        f"[WARNING] Failed to remove PDF text file {pdf_text_file}: {e}"
                    )

            # Remove from memory mapping
            pdf_text_files.pop(pdf_session_id, None)

        # Remove PDF data from session
        session.pop("pdf_session_id", None)
        session.pop("pdf_filename", None)

        return jsonify(
            {"success": True, "message": "PDF data cleared from session and files"}
        )

    except Exception as e:
        print(f"[ERROR] Failed to clear PDF session: {e}")
        return jsonify({"success": False, "message": "Failed to clear PDF data"}), 500


@app.route("/api/test-session", methods=["GET"])
def test_session():
    """Test session functionality"""
    try:
        # Try to set and get a test value
        session["test_value"] = "test_data"
        test_value = session.get("test_value")

        # Check PDF session data
        pdf_session_id = session.get("pdf_session_id")
        pdf_filename = session.get("pdf_filename")
        pdf_text_file = pdf_text_files.get(pdf_session_id) if pdf_session_id else None
        pdf_text_length = 0

        if pdf_text_file and os.path.exists(pdf_text_file):
            try:
                with open(pdf_text_file, "r", encoding="utf-8") as f:
                    pdf_text_length = len(f.read())
            except Exception as e:
                print(f"[WARNING] Failed to read PDF text file: {e}")

        return jsonify(
            {
                "success": True,
                "session_working": test_value == "test_data",
                "session_keys": list(session.keys()),
                "has_pdf_session_id": "pdf_session_id" in session,
                "has_pdf_filename": "pdf_filename" in session,
                "pdf_session_id": pdf_session_id,
                "pdf_filename": pdf_filename,
                "pdf_text_file": pdf_text_file,
                "pdf_text_file_exists": (
                    os.path.exists(pdf_text_file) if pdf_text_file else False
                ),
                "pdf_text_length": pdf_text_length,
            }
        )

    except Exception as e:
        print(f"[ERROR] Session test failed: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": str(e),
                    "session_keys": (
                        list(session.keys()) if hasattr(session, "keys") else []
                    ),
                }
            ),
            500,
        )


def stop_session(session_id):
    """Mark a session for stopping"""
    active_streaming_sessions[session_id] = {"stop_requested": True}
    print(f"[DEBUG] Session {session_id} marked for stopping")


def should_stop_session(session_id):
    """Check if a session should be stopped"""
    session_data = active_streaming_sessions.get(session_id)
    return session_data and session_data.get("stop_requested", False)


def cleanup_session(session_id):
    """Clean up session data"""
    active_streaming_sessions.pop(session_id, None)
    print(f"[DEBUG] Session {session_id} cleaned up")


def cleanup_old_sessions():
    """Clean up sessions older than 1 hour to prevent memory leaks"""
    try:
        current_time = time.time()
        sessions_to_remove = []

        for session_id, session_data in active_streaming_sessions.items():
            # If session has been active for more than 1 hour, mark for removal
            if current_time - session_data.get("created_time", current_time) > 3600:
                sessions_to_remove.append(session_id)

        for session_id in sessions_to_remove:
            cleanup_session(session_id)

        if sessions_to_remove:
            print(f"[DEBUG] Cleaned up {len(sessions_to_remove)} old sessions")

    except Exception as e:
        print(f"[WARNING] Error during session cleanup: {e}")


@app.route("/api/stop", methods=["POST"])
def stop_request():
    """Stop endpoint - forcefully stop all active streaming sessions"""
    try:
        data = request.get_json() or {}
        session_id = data.get("session_id")

        if session_id:
            # Stop specific session
            stop_session(session_id)
            print(f"[DEBUG] Stop request received for session: {session_id}")
            return jsonify(
                {
                    "success": True,
                    "message": f"Stop request received for session {session_id}",
                }
            )
        else:
            # Stop all active sessions
            for sid in list(active_streaming_sessions.keys()):
                stop_session(sid)
            print(f"[DEBUG] Stop request received for all sessions")
            return jsonify(
                {"success": True, "message": "Stop request received for all sessions"}
            )

    except Exception as e:
        print(f"[ERROR] Error in stop request: {e}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500


@app.route("/api/active-sessions", methods=["GET"])
def get_active_sessions():
    """Get information about active streaming sessions (for debugging)"""
    try:
        # Clean up old sessions first
        cleanup_old_sessions()

        sessions_info = {}
        for session_id, session_data in active_streaming_sessions.items():
            sessions_info[session_id] = {
                "stop_requested": session_data.get("stop_requested", False),
                "created_time": session_data.get("created_time", 0),
                "age_seconds": time.time()
                - session_data.get("created_time", time.time()),
            }

        return jsonify(
            {
                "success": True,
                "active_sessions": sessions_info,
                "total_sessions": len(sessions_info),
            }
        )

    except Exception as e:
        print(f"[ERROR] Error getting active sessions: {e}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500


@app.route("/api/continue-generation", methods=["POST"])
def continue_generation():
    data = request.get_json()
    session_id = data.get("session_id")
    if not session_id or session_id not in audio_requests:
        return jsonify({"success": False, "message": "Session not found"}), 404
    request_data = audio_requests[session_id]
    status = request_data.get("status", "unknown")
    if status not in ["stopped", "disconnected"]:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Can only continue from stopped or disconnected requests",
                }
            ),
            400,
        )
    return jsonify(
        {
            "success": True,
            "session_id": session_id,
            "url": request_data["url"],
            "voice": request_data["voice"],
            "service": request_data["service"],
            "completed_chunks": request_data["totalChunks"],
            "completed_duration": request_data["totalDuration"],
            "completed_cost": request_data["cost"],
        }
    )


@app.route("/stream-continue", methods=["GET"])
def stream_continue():
    session_id = request.args.get("session_id")
    voice = request.args.get("voice", "shimmer")
    service = request.args.get("service", "openai")
    if not session_id or session_id not in audio_requests:
        return Response("Session not found", status=404)
    request_data = audio_requests[session_id]
    status = request_data.get("status", "unknown")
    if status not in ["stopped", "disconnected"]:
        return Response("Cannot continue this session", status=400)
    return Response(
        stream_with_context(
            generate_continuation_streaming(session_id, voice, service)
        ),
        mimetype="text/event-stream",
    )


def generate_continuation_streaming(session_id, voice, service):
    try:
        request_data = audio_requests[session_id]
        source_type = request_data.get("source_type", "url")
        if source_type == "url":
            text, source_url = get_text_from_source("url", request_data["url"])
        else:
            text, source_url = get_text_from_source("pdf")
        chunks = chunk_text(text)
        completed_chunks = request_data["totalChunks"]
        existing_chunk_files = []
        for i in range(completed_chunks):
            chunk_file = f"static/chunk_{session_id}_{i}.mp3"
            if os.path.exists(chunk_file):
                existing_chunk_files.append(chunk_file)
        total_cost = request_data["cost"]
        total_duration_so_far = request_data["totalDuration"]
        for idx, chunk in enumerate(chunks[completed_chunks:]):
            chunk_index = completed_chunks + idx
            chunk_cost = calculate_cost(service, len(chunk))
            total_cost += chunk_cost
            if service == "openai":
                audio_bytes = synthesize_with_openai(chunk, voice)
            else:
                audio_bytes = synthesize_with_polly(chunk, voice)
            audio_segment = AudioSegment.from_file(BytesIO(audio_bytes), format="mp3")
            duration_sec = audio_segment.duration_seconds
            chunk_filename = f"static/chunk_{session_id}_{chunk_index}.mp3"
            with open(chunk_filename, "wb") as f:
                f.write(audio_bytes)
            existing_chunk_files.append(chunk_filename)
            total_duration_so_far += duration_sec
            data = {
                "audioUrl": "/" + chunk_filename,
                "chunkDuration": duration_sec,
                "totalDuration": total_duration_so_far,
                "chunkIndex": chunk_index,
                "totalChunks": len(chunks),
                "sessionId": session_id,
                "isContinuation": True,
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(0.5)
        combine_audio_chunks(existing_chunk_files, f"static/combined_{session_id}.mp3")
        audio_requests[session_id]["totalChunks"] = len(existing_chunk_files)
        audio_requests[session_id]["totalDuration"] = total_duration_so_far
        audio_requests[session_id]["cost"] = total_cost
        audio_requests[session_id]["status"] = "completed"
        yield "event: end\ndata: {}\n\n"
    except Exception as e:
        error_data = {"error": str(e)}
        yield f"event: error\ndata: {json.dumps(error_data)}\n\n"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))  # Use Render's PORT if available
    app.run(host="0.0.0.0", port=port, debug=True)
