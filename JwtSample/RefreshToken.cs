// Add these NuGet packages to your project:
// Microsoft.AspNetCore.Authentication.JwtBearer
// System.IdentityModel.Tokens.Jwt

public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; }
    public string Username { get; set; }
    public DateTime ExpiryDate { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime IssuedAt { get; set; }
}
