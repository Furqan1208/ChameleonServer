
# Chameleon: AI-Assisted Adaptive Malware Analysis and Morphing Engine

**A production-ready Blue Team analysis engine with Red Team evasion module for advanced cybersecurity threat detection and response.**

## 🎯 Project Overview

Chameleon is an AI-powered cybersecurity platform that strengthens malware detection through:

- **Blue Team Analysis Engine** (Primary): Behavioral and ML-driven malware detection via dynamic sandbox analysis
- **Red Team Evasion Module** (Supportive): AI-assisted obfuscation for realistic adversarial testing
- **Actionable Intelligence**: MITRE ATT&CK mappings, threat scores, and mitigation recommendations

## 📋 Prerequisites

- **Python**: 3.10+ (tested with 3.14.3)
- **MongoDB**: 6.0+ (local or Atlas)
- **Docker & Docker Compose**: v20.10+ (optional, for containerized deployment)
- **System**: Linux/macOS/Windows with virtualization support (16GB+ RAM recommended for sandbox operations)

## 🚀 Quick Start

### Option 1: Local Development Setup

1. **Clone and navigate to project**
   ```bash
   cd ChameleonServer
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   # For ML features (optional)
   pip install -r requirements-ml.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (see Configuration section below)
   ```

5. **Start the server**
   ```bash
   python server.py
   ```
   - API: http://localhost:8001
   - Interactive Docs: http://localhost:8001/docs
   - Health Check: http://localhost:8001/health

### Option 2: Docker Deployment

1. **Configure environment**
   ```bash
   cp .env.example .env
   # Update .env with your MongoDB URI and API keys
   ```

2. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```
   - API: http://localhost:8001
   - MongoDB: mongodb://localhost:27017

3. **View logs**
   ```bash
   docker-compose logs -f api
   ```

## ⚙️ Configuration

### Required Environment Variables

```env
# JWT Security (REQUIRED - Generate a strong random key)
JWT_SECRET_KEY=<your-secure-random-key-min-32-chars>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# MongoDB
MONGODB_URI=mongodb://localhost:27017/
DB_NAME=chameleon_db

# API Keys (Get from respective services)
VIRUSTOTAL_API_KEY=<your-virustotal-key>
MISP_API_KEY=<your-misp-key>
GEMINI_API_KEY=<your-google-gemini-key>
OPENAI_API_KEY=<your-openai-key>
```

### Optional Configuration

```env
# CORS Settings
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# File Upload
UPLOAD_FILE_SIZE_LIMIT=104857600  # 100MB in bytes

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=900  # 15 minutes

# CAPE Sandbox (if using external CAPE)
CAPE_API_URL=http://localhost:8000/apiv2/
CAPE_API_TOKEN=<your-cape-token>
```

## 📡 API Architecture

### Core Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | ❌ | Welcome & version info |
| `/health` | GET | ❌ | Health check |
| `/auth/register` | POST | ❌ | User registration |
| `/auth/login` | POST | ❌ | User login |
| `/auth/google` | POST | ❌ | Google OAuth |
| `/auth/me` | GET | ✅ | Current user profile |
| `/analysis/complete` | POST | ✅ | Full malware analysis (CAPE→Parse→AI) |
| `/analysis/ai-only` | POST | ✅ | AI analysis only |
| `/analysis/parse-only` | POST | ✅ | Parsing only |
| `/analysis/reports` | GET | ✅ | List user's analyses |
| `/analysis/{analysis_id}` | GET | ✅ | Get analysis details |
| `/users/me` | GET | ✅ | User profile |
| `/users/me/change-password` | POST | ✅ | Change password |

### Authentication

All protected endpoints require a JWT bearer token:

```bash
Authorization: Bearer <jwt_token>
```

## 🏗️ System Architecture

```
Frontend (React/Next.js)
        ↓
   FastAPI Server
   ├── Authentication (JWT + MFA)
   ├── Analysis Engine
   │   ├── Dynamic Sandbox (CAPE)
   │   ├── Static Analysis
   │   ├── External Intel (VirusTotal, MISP, ANY.RUN)
   │   └── ML Classification (XGBoost, Random Forest)
   ├── Red Team Module
   │   └── Malware Obfuscation Engine
   └── Report Generation
        ↓
   MongoDB Database
        ↓
   Storage (Analysis Reports, Models, Datasets)
```

## 🔒 Security Features

- ✅ **JWT Authentication**: Bearer token-based auth with configurable expiry
- ✅ **MFA Support**: TOTP-based multi-factor authentication
- ✅ **Password Security**: bcrypt hashing with 72-byte truncation
- ✅ **CORS Hardening**: Configured for bearer tokens only
- ✅ **Structured Logging**: JSON-formatted logs with context
- ✅ **Environment Isolation**: Secrets via .env (git-ignored)
- ✅ **Database Indexes**: Automatic index creation on startup
- ✅ **Global Exception Handling**: Comprehensive error logging and recovery

## 📊 Analysis Features

### Blue Team Module

- **Dynamic Analysis**: API calls, registry changes, file operations, network traffic
- **Static Analysis**: Hash, file metadata, entropy, packed indicators
- **External Intelligence**: VirusTotal, MISP, ANY.RUN integration
- **ML Classification**: Trained models for malware detection and obfuscation detection
- **Threat Intelligence**: MITRE ATT&CK mapping, behavior-to-technique correlation

### Red Team Module

- **Obfuscation Techniques**: Packing, string encryption, API reordering
- **Detection Evasion**: Generate samples with lowered VirusTotal scores
- **Testing**: AI vs AI feedback loop for adaptive improvement

## 🧪 Testing

### Run Test Suite

```bash
pytest tests/ -v
```

### Manual API Testing

```bash
# Register a user
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "email": "analyst@example.com", "password": "SecureP@ss123"}'

# Login
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "SecureP@ss123"}'

# Upload and analyze malware
curl -X POST http://localhost:8001/analysis/complete \
  -H "Authorization: Bearer <token>" \
  -F "file=@suspicious_sample.exe"
```

## 📁 Project Structure

```
ChameleonServer/
├── app/
│   ├── main.py              # FastAPI application entry
│   ├── config/              # Configuration management
│   ├── models/              # Pydantic models & schemas
│   ├── controllers/         # API route handlers
│   ├── services/            # Business logic
│   ├── database/            # MongoDB operations
│   ├── dependencies/        # FastAPI dependencies
│   ├── ml/                  # ML models & training
│   ├── parser/              # Malware report parsers
│   └── utils/               # Utilities (logging, security, etc.)
├── dataset/                 # ML training datasets
├── requirements.txt         # Core dependencies
├── requirements-ml.txt      # ML dependencies
├── docker-compose.yml       # Docker orchestration
└── .env.example             # Environment template
```

## 🔧 Development

### Adding New Analysis Features

1. **Create parser** in `app/parser/`
2. **Implement service** in `app/services/`
3. **Define API route** in `app/controllers/analysis_routes/`
4. **Add tests** in `tests/`

### Code Quality

```bash
# Format code
ruff format app/

# Lint
ruff check app/

# Type checking
mypy app/
```

## 📚 Documentation

- **Swagger Docs**: http://localhost:8001/docs
- **ReDoc**: http://localhost:8001/redoc
- **Project Proposal**: See FYP proposal document for detailed objectives and scope

## 🤝 Team

- **Anum Mateen** (CR-22002)
- **Furqan Patel** (CR-22032)
- **Tayyab Qamar** (CR-22041) - Lead
- **Iqra Yousuf** (AI-22018)

**Supervisor**: Miss Saadia Arshad, Lecturer, Department of CS & IT

## 📝 License

See LICENSE file for details.

## 🚦 Health Status

Backend Status: **✅ Production Ready**

Last Audit: May 10, 2026
- All routes authenticated and authorized
- Structured JSON logging enabled
- Database indexes auto-created on startup
- Global exception handling in place
- CORS hardened for security
4. Update the main application in `app/main.py`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ for the FastAPI community</sub>
</div>

