# 🔐 JWKS Server with SQLite Database

A robust JSON Web Key Set (JWKS) server implementation in Go with SQLite-backed key persistence, providing secure RSA key management and JWT token issuance for educational purposes.

## ✨ Features

- 💾 **SQLite Persistence**: Keys stored in database survive server restarts
- 🔑 **RSA Key Generation**: Automatically generates 2048-bit RSA key pairs with expiration timestamps
- 🌐 **JWKS Endpoint**: Serves public keys in standard JWKS format at `/.well-known/jwks.json`
- 🎫 **JWT Authentication**: Issues signed JWTs via `/auth` endpoint
- ⏰ **Key Expiration**: Only serves non-expired keys for enhanced security
- 🧪 **Testing Support**: Includes expired token generation for testing scenarios
- 🛡️ **SQL Injection Protection**: Parameterized queries prevent SQL injection attacks
- ✅ **Comprehensive Tests**: 80%+ test coverage with error simulation

## 🚀 Quick Start

### Prerequisites

- Go 1.19 or higher
- SQLite3 (included via go-sqlite3 driver)

### Installation & Running

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/jwks-server-project2.git
   cd jwks-server-project2
   ```

2. **Initialize Go module and install dependencies:**
   ```bash
   # Initialize the Go module
   go mod init jwks-server
   
   # Install required dependencies
   go get github.com/golang-jwt/jwt/v5
   go get github.com/mattn/go-sqlite3
   
   # Tidy up dependencies (optional)
   go mod tidy
   ```

3. **Run the server:**
   ```bash
   go run main.go
   ```

4. **Server starts on port 8080:**
   ```
   JWKS Server starting on :8080
   Database contains 1 valid key(s) and 1 expired key(s)
   ```

## 📡 API Endpoints

### GET `/.well-known/jwks.json`

Returns public keys in JWKS format (only non-expired keys from database).

**Example Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "1",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

### POST `/auth`

Issues a signed JWT token using a valid key from the database.

**Example Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ..."
}
```

### POST `/auth?expired=true`

Issues a JWT signed with an expired key from the database (for testing purposes).

## 💾 Database Schema

**File:** `totally_not_my_privateKeys.db`

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

- `kid`: Auto-incrementing key identifier
- `key`: PEM-encoded RSA private key (BLOB)
- `exp`: Unix timestamp for key expiration

## 🧪 Testing

### Run Test Suite

```bash
# Run all tests
go test

# Run with verbose output
go test -v

# Run with coverage report
go test -cover

# Generate HTML coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

### Manual Testing

```bash
# Test JWKS endpoint
curl http://localhost:8080/.well-known/jwks.json

# Test authentication
curl -X POST http://localhost:8080/auth

# Test expired token generation
curl -X POST "http://localhost:8080/auth?expired=true"

# Pretty print with jq (if installed)
curl -s http://localhost:8080/.well-known/jwks.json | jq .
```

## 📁 Project Structure

```
jwks-server-project2/
├── main.go                              # Server implementation with SQLite
├── main_test.go                         # Test suite with 80%+ coverage
├── go.mod                               # Go module definition
├── go.sum                               # Dependency checksums
├── totally_not_my_privateKeys.db        # SQLite database (auto-generated)
└── README.md                            # This file
```

## 📦 Dependencies

- [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) - JWT token handling
- [`github.com/mattn/go-sqlite3`](https://github.com/mattn/go-sqlite3) - SQLite3 driver for Go

## 🔧 Implementation Details

- **Key Management**: Generates one valid key (24h expiry) and one expired key on first run
- **Persistence**: Keys stored in SQLite with PEM encoding (PKCS1 format)
- **Security**: Parameterized queries prevent SQL injection attacks
- **JWT Claims**: Includes standard claims (sub, exp, iat) with 1-hour token validity
- **Error Handling**: Proper HTTP status codes and error responses
- **Testing**: Comprehensive test coverage including database error simulation

## 💻 Development

### Database Management

```bash
# View database contents
sqlite3 totally_not_my_privateKeys.db "SELECT kid, exp FROM keys;"

# Count keys
sqlite3 totally_not_my_privateKeys.db "SELECT COUNT(*) FROM keys;"

# Delete database (fresh start)
rm totally_not_my_privateKeys.db
```

### Stopping the Server

- Press `Ctrl+C` in the terminal
- Or kill by port: `lsof -ti:8080 | xargs kill`

### Code Style

- Follows Go conventions
- Parameterized SQL queries throughout
- Well-tested with comprehensive error coverage
- Clean separation of concerns (DB layer, handlers, key management)

## ⚠️ Educational Purpose

> **Note**: This project is designed for learning JWKS/JWT concepts and database-backed key management. It should not be used in production without proper authentication, key rotation, and security hardening.
