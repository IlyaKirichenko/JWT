using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using System.Text;
using Microsoft.EntityFrameworkCore.SqlServer.Query.Internal;
using JWT.Services;
using Microsoft.AspNetCore.Authorization;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWT.Controllers
{
    [Route("api/v1/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly JwtContext _context;
        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;
        private readonly RefreshTokenService _refreshTokenService;
        private readonly RevokeTokenService _revocationService;

        public AuthController(JwtContext context, IPasswordHasher<User> hasher, IConfiguration configuration, RefreshTokenService refreshTokenService, RevokeTokenService revocationService)
        {
            _context = context;
            _hasher = hasher;
            _configuration = configuration;
            _refreshTokenService = refreshTokenService;
            _revocationService = revocationService;
        }

        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var credentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ExampleApi",
                audience: "ExampleApiClient",
                claims: claims,
                expires: DateTime.UtcNow.AddSeconds(60),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token); 
        }

        public record AuthRequest(string Login, string Password);

        // POST api/<UserController>
        [HttpPost ("register")]
        public async Task <IActionResult> Register(AuthRequest request)
        {
            if(await _context.Users.AnyAsync(x => x.Login == request.Login))
            {
                return Conflict("Логин уже существует");
            }
            var user = new User 
            {
                Login = request.Login,
                Role = "User"
            };
            user.PasswordHash = _hasher.HashPassword(user, request.Password);

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("Пользователь добавлен");
        }

        [HttpPost ("login")]
        public async Task <IActionResult> Login(AuthRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u=>u.Login == request.Login);

            if(user == null)
            {
                return Unauthorized("Неверная пара логин/пароль");
            }

            var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

            if (result == PasswordVerificationResult.Failed)
            {
                return Unauthorized("Неверная пара логин/пароль");
            }

            var token = GenerateJwtToken(user);

            var refreshToken = await _refreshTokenService.GenerateRefreshToken(user.Id);

            return Ok(new
            {
                access_token = token,
                refresh_token = refreshToken
            });
        }

        public record RefreshRequest(string refresh_token);

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(RefreshRequest request)
        {
            var newRefreshToken = await _refreshTokenService.RotateToken(request.refresh_token);
            if (newRefreshToken == null) return Unauthorized("Refresh Token истек");

            var user = _refreshTokenService.CurrentUser;
            if (user == null) return Unauthorized("Пользователь не найден");

            var newJwt = GenerateJwtToken(user);

            return Ok(new
            {
                access_token = newJwt,
                refresh_token = newRefreshToken
            });
        }
        public record LogoutRequest(string refresh_token);

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout(LogoutRequest request)
        {
            var currentUserLogin = User.Identity?.Name;
    var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
    var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;

    if (string.IsNullOrEmpty(currentUserLogin) || string.IsNullOrEmpty(jti) || string.IsNullOrEmpty(expClaim))
        return Unauthorized();

    if (string.IsNullOrEmpty(request.refresh_token))
        return Unauthorized();

    using var transaction = await _context.Database.BeginTransactionAsync();

    var ownerLogin = await _refreshTokenService.GetTokenOwner(request.refresh_token);
    if (ownerLogin == null) return Unauthorized("Токен не найден или просрочен");
    if (ownerLogin != currentUserLogin) return Forbid();

    var isDeleted = await _refreshTokenService.DeleteTokenForUser(request.refresh_token, currentUserLogin);
    if (!isDeleted) return Unauthorized();

    var expDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime;
    await _revocationService.Revoke(jti, expDate);

    await transaction.CommitAsync();

    return NoContent(); 
        }
    }
}
