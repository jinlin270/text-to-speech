# Streaming TTS Reader

A web application that converts articles to speech using OpenAI TTS or AWS Polly, with usage tracking and authentication.

## Features

- **Dual TTS Services**: OpenAI TTS and AWS Polly (75% cheaper)
- **Usage Tracking**: Configurable limit with real-time monitoring
- **Authentication**: Special access for Lin to bypass usage limits and manage usage
- **Streaming Audio**: YouTube-like experience with chunk navigation
- **History**: Track all past audio requests
- **Cost Optimization**: Automatic cleanup of temporary files

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file or set these environment variables:

```bash
# Required for OpenAI TTS
OPENAI_API_KEY=your_openai_api_key_here

# Required for AWS Polly (optional, for cost savings)
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_REGION=us-east-1

# Required for authentication
LIN_PASSWORD=your_secure_password_for_lin
PASSWORD_SALT=your_random_salt_string

# Usage limit (optional, defaults to $0.01)
USAGE_LIMIT=0.01

# Optional (auto-generated if not set)
SECRET_KEY=your_flask_secret_key
```

### 3. Security Notes

- **LIN_PASSWORD**: Set a strong password for Lin's account
- **PASSWORD_SALT**: Use a random string to salt password hashes
- **SECRET_KEY**: Flask session encryption key (auto-generated if not set)
- **USAGE_LIMIT**: Set the default usage limit in dollars
- Never commit these values to version control

### 4. Run the Application

```bash
python app.py
```

The application will be available at `http://localhost:5001`

## Usage

### Regular Users

- Configurable usage limit (default: $0.01)
- Can choose between OpenAI TTS and AWS Polly
- Real-time usage tracking
- History of all requests

### Lin (Authenticated User)

- Username: `lin`
- Password: Set via `LIN_PASSWORD` environment variable
- Unlimited usage after login
- Can reset usage to $0.00
- Can change the usage limit for all users
- Bypasses usage limits

## Cost Information

- **OpenAI TTS**: $0.015 per 1K characters
- **AWS Polly**: $0.004 per 1K characters (75% cheaper)
- **Usage Limit**: Configurable (default: $0.01)

## Security Features

- Password hashing with salt
- Rate limiting on login attempts (5 attempts per 5 minutes)
- Session-based authentication
- Environment variable configuration
- Automatic cleanup of temporary files

## API Endpoints

- `GET /` - Main application
- `GET /api/usage` - Get current usage information
- `POST /api/usage` - Update usage (Lin only: reset usage or change limit)
- `POST /api/login` - Authenticate Lin
- `POST /api/logout` - Logout
- `GET /api/requests` - Get request history
- `GET /stream-read` - Stream audio generation

## Lin's Management Features

When logged in as Lin, you can:

1. **Reset Usage**: Set current usage back to $0.00
2. **Change Limit**: Modify the usage limit for all users
3. **Unlimited Access**: Generate audio without usage restrictions

## File Structure

```
├── app.py              # Main Flask application
├── templates/
│   └── index.html      # Frontend interface
├── static/             # Audio files (auto-created)
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Troubleshooting

1. **Authentication not working**: Check `LIN_PASSWORD` environment variable
2. **AWS Polly not working**: Verify AWS credentials and region
3. **OpenAI not working**: Check `OPENAI_API_KEY` environment variable
4. **Usage limit errors**: Login as Lin or wait for usage to reset
5. **Login JSON errors**: Check server logs for detailed error messages

## Security Best Practices

1. Use strong, unique passwords
2. Set a random salt for password hashing
3. Keep environment variables secure
4. Regularly rotate API keys
5. Monitor usage and login attempts
6. Set appropriate usage limits for your budget
