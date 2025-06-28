from flask import Flask, request, jsonify, send_file
import openai
import requests
from io import BytesIO
from newspaper import Article
import os
import textwrap
import uuid

from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allow cross-origin if frontend is hosted separately

openai.api_key = os.getenv("OPENAI_API_KEY")


def chunk_text(text, max_chars=3500):
    # Split on paragraph boundaries if possible
    paragraphs = text.split("\n")
    chunks, chunk = [], ""
    for para in paragraphs:
        if len(chunk) + len(para) < max_chars:
            chunk += para + "\n"
        else:
            chunks.append(chunk.strip())
            chunk = para + "\n"
    if chunk:
        chunks.append(chunk.strip())
    return chunks


@app.route("/read-url", methods=["POST"])
def read_url():
    data = request.json
    url = data.get("url")
    voice = data.get("voice", "shimmer")  # default to shimmer if not specified

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Validate voice input (optional but recommended)
    allowed_voices = {"shimmer", "onyx", "nova", "echo", "fable"}
    if voice not in allowed_voices:
        return (
            jsonify(
                {
                    "error": f"Invalid voice '{voice}'. Allowed voices: {', '.join(allowed_voices)}"
                }
            ),
            400,
        )

    try:
        article = Article(url)
        article.download()
        article.parse()
        text = article.text

        chunks = chunk_text(text)  # Make sure chunk_text is defined somewhere

        audio_urls = []
        for idx, chunk in enumerate(chunks):
            response = openai.audio.speech.create(
                model="tts-1", voice=voice, input=chunk
            )
            audio_data = BytesIO(response.content)
            filename = f"chunk_{uuid.uuid4().hex}.mp3"
            with open(f"static/{filename}", "wb") as f:
                f.write(audio_data.read())
            audio_urls.append(f"/static/{filename}")

        return jsonify({"audioChunks": audio_urls})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
