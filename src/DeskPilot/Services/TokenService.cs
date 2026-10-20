using System.Security.Cryptography;
using System.Text;
using DeskPilot.Data;
using Microsoft.EntityFrameworkCore;

namespace DeskPilot.Services;

public record ClientDevice(string? Id, string? Uuid, string? Os, string? Type, string? Name, string? Ip);

public class TokenService(AppDbContext db, SettingsService settings)
{
    public static string NewToken(int bytes = 32)
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Hash(string token)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public async Task<string> IssueAsync(User user, ClientDevice device)
    {
        var days = await settings.GetIntAsync(SettingKeys.AccessTokenDays, 30);
        var token = NewToken();
        // One token per (user, client uuid): logging in again from the same client replaces the old one.
        if (!string.IsNullOrEmpty(device.Uuid))
            await db.AccessTokens.Where(t => t.UserId == user.Id && t.ClientUuid == device.Uuid).ExecuteDeleteAsync();
        db.AccessTokens.Add(new AccessToken
        {
            TokenHash = Hash(token),
            UserId = user.Id,
            ClientId = device.Id,
            ClientUuid = device.Uuid,
            DeviceOs = device.Os,
            DeviceType = device.Type,
            DeviceName = device.Name,
            Ip = device.Ip,
            ExpiresAt = DateTime.UtcNow.AddDays(days),
        });
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return token;
    }

    /// <summary>Resolves a client bearer token (from /api/login) or an API token.</summary>
    public async Task<(User? User, AccessToken? Token)> ValidateAsync(string? authorization)
    {
        var raw = ExtractBearer(authorization);
        if (raw is null) return (null, null);
        var hash = Hash(raw);
        var now = DateTime.UtcNow;

        var at = await db.AccessTokens.Include(t => t.User).FirstOrDefaultAsync(t => t.TokenHash == hash);
        if (at is not null)
        {
            if (at.ExpiresAt < now || at.User is null || at.User.Status != UserStatus.Normal) return (null, null);
            if (now - at.LastUsedAt > TimeSpan.FromMinutes(5))
            {
                at.LastUsedAt = now;
                await db.SaveChangesAsync();
            }
            return (at.User, at);
        }

        var api = await db.ApiTokens.Include(t => t.User).FirstOrDefaultAsync(t => t.TokenHash == hash);
        if (api is not null && (api.ExpiresAt is null || api.ExpiresAt > now) && api.User?.Status == UserStatus.Normal)
        {
            api.LastUsedAt = now;
            await db.SaveChangesAsync();
            return (api.User, null);
        }
        return (null, null);
    }

    public async Task RevokeAsync(string? authorization)
    {
        var raw = ExtractBearer(authorization);
        if (raw is null) return;
        var hash = Hash(raw);
        await db.AccessTokens.Where(t => t.TokenHash == hash).ExecuteDeleteAsync();
    }

    private static string? ExtractBearer(string? authorization)
    {
        if (string.IsNullOrWhiteSpace(authorization)) return null;
        const string prefix = "Bearer ";
        var raw = authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? authorization[prefix.Length..].Trim()
            : null;
        return string.IsNullOrEmpty(raw) ? null : raw;
    }
}
