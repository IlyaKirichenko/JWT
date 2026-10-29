using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWT.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly List<User> _users;
        private readonly IPasswordHasher<User> _hasher;

        public AuthController(List<User> users, IPasswordHasher<User> hasher)
        {
            _users = users;
            _hasher = hasher;
        }

        public record AuthRequest(string Login, string Password);

        // POST api/<UserController>
        [HttpPost ("register")]
        public IActionResult Register(AuthRequest request)
        {
            if(_users.Any(x => x.Login == request.Login))
            {
                return Conflict("Логин уже существует");
            }
            var user = new User {Login = request.Login};
            user.PasswordHash = _hasher.HashPassword(user, request.Password);

            _users.Add(user);

            return Ok("ПОльзователь добавлен");
        }

        [HttpPost ("login")]
        public IActionResult Login(AuthRequest request)
        {

        }

        // PUT api/<UserController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<UserController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
