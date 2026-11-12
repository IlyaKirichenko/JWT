using JWT.Models;
using System.Text;

using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace JWT.Services
{
    public class RefreshTokenService
    {
        private readonly JwtContext _context;


        public RefreshTokenService(JwtContext context)
        {
            _context = context;
        }

        public async Task<string> GenerateRefreshToken(int userId)
        {
            var randomBytes = RandomNumberGenerator.GetBytes(32);
            string convToken = Convert.ToBase64String(randomBytes);

            var term7d = DateTime.UtcNow.AddDays(7);

            var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(convToken));
            var tokenHash = Convert.ToHexString(hashBytes);

            var newRefreshToken = new RefreshToken
            {
                UserId = userId,
                TokenHash = tokenHash,
                ExpiresAt = term7d
            };

            _context.RefreshTokens.Add(newRefreshToken);
            await _context.SaveChangesAsync();

            return convToken;
        }

        public async Task<string> RotateToken(string oldToken)
        {
            var oldHashToken = SHA256.HashData(Encoding.UTF8.GetBytes(oldToken));
            var oldHash = Convert.ToHexString(oldHashToken);

            var exsitingHash = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == oldHash);

            if (exsitingHash == null)
            {
                return null;
            }



            var userId = exsitingHash.UserId;

            var now = DateTime.UtcNow;

            var deletedToken = await _context.RefreshTokens
                .Where(d => d.TokenHash == oldToken && d.ExpiresAt > now)
                .ExecuteDeleteAsync();

            if(deletedToken == 0)
            {
                return null;
            }

            var newToken = await GenerateRefreshToken(userId);

            return newToken;
        }
    }
}
