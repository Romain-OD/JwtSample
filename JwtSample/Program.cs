// Add these NuGet packages to your project:
// Microsoft.AspNetCore.Authentication.JwtBearer
// System.IdentityModel.Tokens.Jwt

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure Services
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]!)
        )
    };
});

builder.Services.AddAuthorization();
builder.Services.AddScoped<JwtAuthService>();

var app = builder.Build();

// Configure middleware
app.UseAuthentication();
app.UseAuthorization();

// Group API endpoints
var authGroup = app.MapGroup("/api/auth");

// Login endpoint
authGroup.MapPost("/login", async (LoginRequest request, JwtAuthService jwtService) =>
{
    // In a real application, validate credentials here
    if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest("Invalid credentials");
    }

    var token = jwtService.GenerateToken(
        "userId", // In real app, use actual user ID
        request.Email,
        new[] { "User" }
    );

    return Results.Ok(new TokenResponse(token));
})
.WithName("Login")
.WithOpenApi();

// Protected endpoint
authGroup.MapGet("/protected", (ClaimsPrincipal user) =>
{
    var email = user.FindFirst(ClaimTypes.Email)?.Value;
    return Results.Ok(new ProtectedResponse($"Protected endpoint accessed by {email}"));
})
.RequireAuthorization()
.WithName("Protected")
.WithOpenApi();

app.Run();