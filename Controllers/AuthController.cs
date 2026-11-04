using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWT.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly JwtContext _context;
        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;

        public AuthController(JwtContext context, IPasswordHasher<User> hasher, IConfiguration configuration)
        {
            _context = context;
            _hasher = hasher;
            _configuration = configuration;
        }

        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var credentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ExampleApi",
                audience: "ExampleApiClient",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
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

            return Ok(new
            {
                access_token = token
            });
        }
    }
}
