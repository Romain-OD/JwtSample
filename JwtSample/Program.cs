// Add these NuGet packages to your project:
// Microsoft.AspNetCore.Authentication.JwtBearer
// System.IdentityModel.Tokens.Jwt

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data.Entity;
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
        ClockSkew = TimeSpan.Zero,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]!)
        )
    };
});

builder.Services.AddAuthorization();
builder.Services.AddScoped<JwtAuthService>();
builder.Services.AddScoped<AuthDbContext>();

var app = builder.Build();

// Configure middleware
app.UseAuthentication();
app.UseAuthorization();

// Group API endpoints
var authGroup = app.MapGroup("/api/auth");

// Login endpoint
authGroup.MapPost("/login", async (LoginRequest request, JwtAuthService jwtService, AuthDbContext dbContext) =>
{
    // In a real application, validate credentials here
    if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest("Invalid credentials");
    }

    // Generate token pair
    var (accessToken, refreshToken) = jwtService.GenerateTokens(request.Email);

    // Store refresh token in database
    var refreshTokenEntity = new RefreshToken
    {
        Token = refreshToken,
        Username = request.Email,
        ExpiryDate = DateTime.UtcNow.AddDays(7),
        IsRevoked = false,
        IssuedAt = DateTime.UtcNow
    };

    dbContext.RefreshTokens.Add(refreshTokenEntity);
    await dbContext.SaveChangesAsync();

    return Results.Ok(new
    {
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        ExpiresIn = 1200 // 20 minutes in seconds
    });
})
.WithName("Login")
.WithOpenApi();

app.MapPost("/refresh-token", async (RefreshTokenRequest request, AuthDbContext dbContext, JwtAuthService jwtService) =>
{
    // Validate refresh token
    var storedToken = await dbContext.RefreshTokens
        .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken && !rt.IsRevoked);

    if (storedToken == null || storedToken.ExpiryDate < DateTime.UtcNow)
    {
        return Results.Unauthorized();
    }

    // Generate new token pair
    var (newAccessToken, newRefreshToken) = jwtService.GenerateTokens(storedToken.Username);

    // Revoke old refresh token (optional rotation)
    storedToken.IsRevoked = true;

    // Store new refresh token
    var refreshTokenEntity = new RefreshToken
    {
        Token = newRefreshToken,
        Username = storedToken.Username,
        ExpiryDate = DateTime.UtcNow.AddDays(7),
        IsRevoked = false,
        IssuedAt = DateTime.UtcNow
    };

    dbContext.RefreshTokens.Add(refreshTokenEntity);
    await dbContext.SaveChangesAsync();

    return Results.Ok(new
    {
        AccessToken = newAccessToken,
        RefreshToken = newRefreshToken,
        ExpiresIn = 1200 // 20 minutes in seconds
    });
});

// Logout/revoke endpoint
app.MapPost("/revoke", [Authorize] async (RefreshTokenRequest request, AuthDbContext dbContext) =>
{
    var storedToken = await dbContext.RefreshTokens
        .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

    if (storedToken != null)
    {
        storedToken.IsRevoked = true;
        await dbContext.SaveChangesAsync();
    }

    return Results.Ok(new { Message = "Token successfully revoked" });
});


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
