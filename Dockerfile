FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && \
  apt-get install -y ffmpeg libmagic-dev curl && \
  apt-get clean

# Set working directory
WORKDIR /app

# Copy app files
COPY . /app

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN apt-get update && \
  apt-get install -y ffmpeg libmagic-dev && \
  apt-get clean


# Expose Flask port
EXPOSE 5001

# Run the app
CMD ["python", "app.py"]
