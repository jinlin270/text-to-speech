# Streaming TTS Reader

A Flask-based web application that converts articles and PDFs to speech using OpenAI TTS and AWS Polly. Features streaming audio chunks, seamless playback, usage tracking, and authentication.

## Features

- **Dual TTS Services**: OpenAI TTS and AWS Polly (cheaper alternative)
- **Multiple Input Sources**:
  - URL-based article extraction
  - PDF file upload and text extraction
- **Streaming Audio**: Real-time audio generation with chunk-by-chunk playback
- **Seamless Playback**: YouTube-like experience with no audio cuts
- **Usage Tracking**: Configurable usage limits with cost tracking
- **Authentication**: Login system for admin access
- **History Management**: Track and replay past audio requests
- **Voice Selection**: Multiple voices for each TTS service
- **Responsive UI**: Modern, user-friendly interface

## Setup

### Prerequisites

- Python 3.8+
- OpenAI API key
- AWS credentials (optional, for Polly)

### Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd audio
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set up environment variables:

```bash
# Required
export OPENAI_API_KEY="your-openai-api-key"
export SECRET_KEY="your-secret-key"
export LIN_PASSWORD="your-admin-password"
export PASSWORD_SALT="your-password-salt"

# Optional (for AWS Polly)
export AWS_ACCESS_KEY_ID="your-aws-access-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-key"
export AWS_REGION="us-east-1"

# Optional (usage limits)
export USAGE_LIMIT="15.00"  # Default: $10.00
```

4. Run the application:

```bash
python app.py
```

The app will be available at `http://localhost:5001`

## Usage

### URL Mode

1. Select the "URL" tab
2. Enter an article URL
3. Choose TTS service (OpenAI or AWS Polly)
4. Select a voice
5. Click "Read Article"

### PDF Mode

1. Select the "PDF" tab
2. Upload a PDF file (drag & drop or click to browse)
3. Wait for text extraction
4. Choose TTS service and voice
5. Click "Read PDF"

### Features

- **Streaming**: Audio plays as it's generated
- **Navigation**: Use arrow buttons to navigate between chunks
- **Full Audio**: Complete audio file available after generation
- **History**: View and replay past requests
- **Usage Tracking**: Monitor costs and limits
- **Admin Access**: Login as "lin" to manage usage limits

## Security

- Passwords are hashed with salt
- Rate limiting on login attempts
- Session-based authentication
- Environment variable configuration
- Input validation and sanitization

## API Endpoints

- `GET /` - Main application
- `GET /stream-read` - Stream audio from URL
- `GET /stream-pdf` - Stream audio from PDF
- `POST /api/upload-pdf` - Upload and process PDF
- `GET /api/usage` - Get usage information
- `POST /api/usage` - Update usage limits (admin only)
- `POST /api/login` - User authentication
- `POST /api/logout` - User logout
- `GET /api/requests` - Get request history
- `GET /api/test` - Test configuration

## Cost Tracking

- **OpenAI TTS**: $0.015 per 1K characters
- **AWS Polly**: $0.004 per 1K characters
- Configurable usage limits
- Real-time cost tracking
- Admin can reset usage and change limits

## Dependencies

- Flask - Web framework
- OpenAI - TTS service
- Newspaper3k - Article extraction
- PyPDF2 - PDF text extraction
- Pydub - Audio processing
- Boto3 - AWS Polly integration
- Flask-CORS - Cross-origin support

## Troubleshooting

### Common Issues

1. **PDF Upload Fails**: Ensure PDF contains extractable text (not scanned images)
2. **AWS Polly Errors**: Check AWS credentials and region configuration
3. **Rate Limiting**: Some websites may block requests; try different URLs
4. **Audio Cuts Off**: Ensure sufficient disk space for temporary files

### Debug Mode

Enable debug logging by setting environment variables:

```bash
export FLASK_DEBUG=1
```

## License

This project is licensed under the MIT License.
