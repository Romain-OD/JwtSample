## JWT Authentication Sample in .NET 9

This project demonstrates the implementation of JWT (JSON Web Token) authentication in a .NET 9 minimal API application. It provides a secure way to handle user authentication and protect API endpoints.

## Features

- JWT token generation and validation
- Minimal API implementation
- Configuration validation
- HTTP file for API testing
- Role-based authorization
- Environment-specific configuration

## Prerequisites

- .NET 9 SDK
- Visual Studio 2022 or VS Code
- REST Client extension (for VS Code) if using .http files

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/JwtSample.git
cd JwtSample
```

2. Install required NuGet packages:
```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package System.IdentityModel.Tokens.Jwt
```

3. Configure JWT settings in `appsettings.json`:
```json
{
  "Jwt": {
    "SecretKey": "your-very-long-secret-key-here-min-32-characters",
    "Issuer": "your-issuer",
    "Audience": "your-audience"
  }
}
```


## Testing with .http Files

The project includes a `.http` file for testing the API endpoints.

Example request:
```http
@hostname = http://localhost:5039

### Login to get JWT token
# @name login
POST {{hostname}}/api/auth/login
Content-Type: application/json
{
    "email": "user@example.com",
    "password": "password123"
}

### Access protected endpoint using the JWT token
GET {{hostname}}/api/auth/protected
Authorization: Bearer {{login.response.body.$.token}}

```

## Configuration

### JWT Settings
- `SecretKey`: The key used to sign the JWT token (minimum 32 characters)
- `Issuer`: The issuer of the JWT token
- `Audience`: The intended audience of the JWT token

### Environment-specific Configuration
Create an `appsettings.Development.json` for development settings:
```json
{
  "Jwt": {
    "SecretKey": "development-secret-key-that-is-at-least-32-characters",
    "Issuer": "development-issuer",
    "Audience": "development-audience"
  }
}
```

## Security Considerations

1. Store sensitive configuration in user secrets during development:
```bash
dotnet user-secrets set "Jwt:SecretKey" "your-secret-key"
```

2. Use strong secret keys (minimum 32 characters)
3. Implement proper password hashing in production
4. Use HTTPS in production
5. Set appropriate token expiration times

## API Endpoints

### POST /api/auth/login
Authenticates a user and returns a JWT token.

Request:
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

Response:
```json
{
    "token": "eyJhbGci..."
}
```

### GET /api/auth/protected
A protected endpoint that requires a valid JWT token.

Header:
```
Authorization: Bearer <token>
```

Response:
```json
{
    "message": "Protected endpoint accessed by user@example.com"
}
```

## Error Handling

The application includes validation for:
- Missing or invalid JWT configuration
- Invalid login credentials
- Invalid or expired tokens
- Unauthorized access attempts

## Refresh Token

![Untitled diagram-2025-02-19-094254](https://github.com/user-attachments/assets/f3a61691-4e15-4bac-b6f5-0253ed4ff9b3)


## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
