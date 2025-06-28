from flask import Flask, request, Response, stream_with_context, render_template
import openai
from newspaper import Article
import time
import json
import uuid
from io import BytesIO
import os
import yaml

from flask_cors import CORS

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


# @app.route("/read-url", methods=["POST"])
# def read_url():
#     data = request.json
#     url = data.get("url")
#     voice = data.get("voice", "shimmer")  # default to shimmer if not specified

#     if not url:
#         return jsonify({"error": "No URL provided"}), 400

#     # Validate voice input (optional but recommended)
#     allowed_voices = {"shimmer", "onyx", "nova", "echo", "fable"}
#     if voice not in allowed_voices:
#         return (
#             jsonify(
#                 {
#                     "error": f"Invalid voice '{voice}'. Allowed voices: {', '.join(allowed_voices)}"
#                 }
#             ),
#             400,
#         )

#     try:
#         article = Article(url)
#         article.download()
#         article.parse()
#         text = article.text

#         chunks = chunk_text(text)  # Make sure chunk_text is defined somewhere

#         audio_urls = []
#         for idx, chunk in enumerate(chunks):
#             response = openai.audio.speech.create(
#                 model="tts-1", voice=voice, input=chunk
#             )
#             audio_data = BytesIO(response.content)
#             filename = f"chunk_{uuid.uuid4().hex}.mp3"
#             with open(f"static/{filename}", "wb") as f:
#                 f.write(audio_data.read())
#             audio_urls.append(f"/static/{filename}")

#         return jsonify({"audioChunks": audio_urls})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route("/stream-read", methods=["GET"])
def stream_read():
    url = request.args.get("url")
    voice = request.args.get("voice", "shimmer")

    print("[DEBUG] Received request for URL:", url)
    print("[DEBUG] Selected voice:", voice)

    if not url:
        print("[ERROR] No URL provided")
        return Response("No URL provided", status=400)

    def generate(voice):
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

                # Save audio to file
                filename = f"static/chunk_{uuid.uuid4().hex}.mp3"
                with open(filename, "wb") as f:
                    f.write(response.content)

                print(f"[DEBUG] Audio saved as {filename}")

                # Send audio chunk URL to frontend
                data = {"audioUrl": "/" + filename}
                yield f"data: {json.dumps(data)}\n\n"

                # Short delay to pace the stream
                time.sleep(0.5)

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
