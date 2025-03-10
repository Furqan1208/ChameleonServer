# 🚀 FastAPI REST Backend with MongoDB

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

A production-ready template for building scalable RESTful APIs with FastAPI and MongoDB.

</div>

## ✨ Features

- **⚡ FastAPI**: High-performance, easy-to-use web framework
- **🍃 MongoDB**: Asynchronous NoSQL database integration with Motor
- **🔍 Swagger UI**: Interactive API documentation out-of-the-box
- **🔒 JWT Auth**: Ready-to-use authentication system
- **🧩 Modular Design**: Clean architecture with separation of concerns
- **🐳 Docker Ready**: Containerized deployment with Docker Compose
- **🔄 Async/Await**: Fully asynchronous API endpoints
- **📊 Pydantic Models**: Robust data validation and serialization

## 📋 Project Structure

```
fastapi-mongodb-template/
├── app/
│   ├── __init__.py            # Package initialization
│   ├── main.py                # Application entry point
│   ├── models/                # Data models
│   │   ├── user.py            # User schema definitions
│   ├── controllers/           # API route handlers
│   │   ├── user_routes.py     # User endpoints
│   ├── services/              # Business logic
│   │   ├── user_service.py    # User operations
│   ├── database/              # Database connections
│   │   ├── mongodb.py         # MongoDB configuration
│   └── utils/                 # Utility functions
│       └── auth.py            # Authentication helpers
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variables template
├── Dockerfile                 # Container configuration
└── docker-compose.yml         # Multi-container setup
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- MongoDB (local or Atlas)
- Docker and Docker Compose (optional)

### Option 1: Local Development

1. **Clone the repository**

2. **Set up a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run the application**
   ```bash
   python server.py
   ```

6. **Access the API**
   - API Endpoints: [http://localhost:8000](http://localhost:8000)
   - Interactive Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

### Option 2: Docker Deployment

1. **Clone the repository**

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Build and start containers**
   ```bash
   docker-compose up -d
   ```

4. **Access the API**
   - API Endpoints: [http://localhost:8000](http://localhost:8000)
   - Interactive Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/` | Welcome message |
| GET    | `/users/` | Retrieve all users |
| GET    | `/users/{user_id}` | Get user by ID |
| POST   | `/users/` | Create a new user |
| PUT    | `/users/{user_id}` | Update a user |
| DELETE | `/users/{user_id}` | Delete a user |

## 📝 API Examples

### Create a User

```bash
curl -X POST http://localhost:8000/users/ \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "profile_picture": "https://example.com/john.jpg"}'
```

### Get All Users

```bash
curl -X GET http://localhost:8000/users/
```

## 🧪 Testing

Run the tests with:

```bash
pytest
```

## 🛠️ Development

### Adding New Features

1. Create new models in `app/models/`
2. Implement business logic in `app/services/`
3. Define API routes in `app/controllers/`
4. Update the main application in `app/main.py`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ for the FastAPI community</sub>
</div>

