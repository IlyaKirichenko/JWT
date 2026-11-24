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

        public User? CurrentUser { get; set; }

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

        public async Task<string?> RotateToken(string oldToken)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var oldHashToken = SHA256.HashData(Encoding.UTF8.GetBytes(oldToken));
                var oldHash = Convert.ToHexString(oldHashToken);

                var existingToken = await _context.RefreshTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == oldHash);

                var now = DateTime.UtcNow;

                if (existingToken == null || existingToken.ExpiresAt <= now || existingToken.User == null)
                {
                    return null;
                }

                CurrentUser = existingToken.User;

                _context.RefreshTokens.Remove(existingToken);
                await _context.SaveChangesAsync();

                var newToken = await GenerateRefreshToken(CurrentUser.Id);

                await transaction.CommitAsync();

                return newToken;
            }
            catch
            {
                await transaction.RollbackAsync();
                return null;
            }
        }
        public async Task<string?> GetTokenOwner(string token)
        {
            var now = DateTime.UtcNow;
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
            var refreshToken = await _context.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.TokenHash == hash && r.ExpiresAt > now);

            return refreshToken?.User?.Login;
        }
        public async Task<bool> DeleteTokenForUser(string token, string login)
        {
            var now = DateTime.UtcNow;
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
            var refreshToken = await _context.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.TokenHash == hash && r.User.Login == login && r.ExpiresAt > now);

            if (refreshToken == null) return false;

            _context.RefreshTokens.Remove(refreshToken);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
