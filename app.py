from flask import Flask, request, Response, stream_with_context, render_template
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

app = Flask(__name__)
CORS(app)  # allow cross-origin if frontend is hosted separately


def load_secrets(path="secrets.yml"):
    with open(path, "r") as file:
        secrets = yaml.safe_load(file)
    return secrets


secrets = load_secrets()

openai.api_key = secrets["api-keys"]["open-api"]


@app.route("/")
def index():
    return render_template("index.html")


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


@app.route("/stream-read", methods=["GET"])
def stream_read():
    url = request.args.get("url")
    voice = request.args.get("voice", "shimmer")

    print("[DEBUG] Received request for URL:", url)
    print("[DEBUG] Selected voice:", voice)

    if not url:
        print("[ERROR] No URL provided")
        return Response("No URL provided", status=400)

    # Clean up old files before starting
    cleanup_old_audio_files()

    def generate(voice):
        chunk_files = []
        session_id = uuid.uuid4().hex
        combined_audio_path = f"static/combined_{session_id}.mp3"

        try:
            print("[DEBUG] Starting article parsing...")
            article = Article(url)
            article.download()
            article.parse()
            text = article.text
            print("[DEBUG] Article downloaded and parsed, text length:", len(text))

            chunks = chunk_text(text)
            print(f"[DEBUG] Text split into {len(chunks)} chunk(s).")

            allowed_voices = {"shimmer", "onyx", "nova", "echo", "fable"}
            if voice not in allowed_voices:
                print(f"[WARNING] Invalid voice '{voice}', defaulting to shimmer.")
                voice = "shimmer"

            for idx, chunk in enumerate(chunks):
                print(f"[DEBUG] Synthesizing chunk {idx + 1}/{len(chunks)}...")

                # Call OpenAI TTS API
                response = openai.audio.speech.create(
                    model="tts-1", voice=voice, input=chunk
                )
                print("[DEBUG] TTS request complete, saving audio...")
                audio_bytes = response.content
                audio_segment = AudioSegment.from_file(
                    BytesIO(audio_bytes), format="mp3"
                )
                duration_sec = audio_segment.duration_seconds

                # Save individual chunk to file
                chunk_filename = f"static/chunk_{session_id}_{idx}.mp3"
                with open(chunk_filename, "wb") as f:
                    f.write(response.content)

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

            print("[DEBUG] Streaming complete.")
            yield "event: end\ndata: {}\n\n"

        except Exception as e:
            print("[ERROR] Exception occurred:", str(e))
            import traceback

            traceback.print_exc()

            error_data = {"error": str(e)}
            yield f"event: error\ndata: {json.dumps(error_data)}\n\n"

    return Response(stream_with_context(generate(voice)), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
