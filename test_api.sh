#!/bin/bash

# Define base API URL
BASE_URL="http://localhost:8000"

# Function to check if the server is running
check_server() {
    echo "Checking if FastAPI server is running..."
    if curl -s "$BASE_URL" | grep -q "Welcome to the FastAPI with MongoDB Atlas API"; then
        echo "✅ Server is running"
    else
        echo "❌ Server is not running. Start it with: uvicorn app.main:app --reload"
        exit 1
    fi
}

# Test fetching all users
test_get_users() {
    echo "Testing GET /users/..."
    curl -s -X GET "$BASE_URL/users/" | jq .
}

# Test creating a new user
test_create_user() {
    echo "Testing POST /users/..."
    curl -s -X POST "$BASE_URL/users/" -H "Content-Type: application/json" -d '{
        "name": "Test User",
        "email": "testuser@example.com"
    }' | jq .
}

# Test updating a user (Replace USER_ID with a valid one)
test_update_user() {
    echo "Testing PUT /users/{user_id}..."
    USER_ID="67cdf37fa694019dff248b52"
    curl -s -X PUT "$BASE_URL/users/$USER_ID" -H "Content-Type: application/json" -d '{
        "name": "Updated User"
    }' | jq .
}

# Test deleting a user (Replace USER_ID with a valid one)
test_delete_user() {
    echo "Testing DELETE /users/{user_id}..."
    USER_ID="67cdf37fa694019dff248b52"
    curl -s -X DELETE "$BASE_URL/users/$USER_ID"
}


check_server
test_get_users
test_create_user
test_update_user
test_delete_user
