using JWT.Models;
using Microsoft.EntityFrameworkCore;
using Task = System.Threading.Tasks.Task;

namespace JWT.Services
{
    public class RevokeTokenService
    {
        private readonly JwtContext _context;

        public RevokeTokenService(JwtContext context)
        {
            _context = context;
        }

        public async Task<bool> IsRevoked(string jti)
        {
            var now = DateTime.UtcNow;
            var expired = await _context.RevokedTokens
                .Where(t => t.ExpiresAt < now)
                .ToListAsync();

            if (expired.Any())
            {
                _context.RevokedTokens.RemoveRange(expired);
                await _context.SaveChangesAsync();
            }

            return await _context.RevokedTokens.AnyAsync(t => t.Jti == jti);
        }

        public async Task Revoke(string jti, DateTime expiresAt)
        {
            _context.RevokedTokens.Add(new RevokedToken { Jti = jti, ExpiresAt = expiresAt });
            await _context.SaveChangesAsync();
        }
    }
}