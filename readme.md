


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

