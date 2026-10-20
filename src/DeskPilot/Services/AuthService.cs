using DeskPilot.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OtpNet;

namespace DeskPilot.Services;

public record AuthResult(User? User, string? Error, bool NeedsTfa = false, string? TfaChallenge = null);

public class AuthService(AppDbContext db, LdapService ldap, SettingsService settings, IMemoryCache cache, ILogger<AuthService> log)
{
    private static readonly PasswordHasher<User> Hasher = new();
    private const int MaxFailures = 10;
    private static readonly TimeSpan LockWindow = TimeSpan.FromMinutes(10);

    public static string HashPassword(User u, string password) => Hasher.HashPassword(u, password);

    public static bool VerifyPassword(User u, string password)
        => u.PasswordHash is not null && Hasher.VerifyHashedPassword(u, u.PasswordHash, password) != PasswordVerificationResult.Failed;

    /// <summary>First factor. When TOTP is enabled returns a challenge to send back with the code.</summary>
    public async Task<AuthResult> PasswordLoginAsync(string? username, string? password, string? ip)
    {
        username = username?.Trim() ?? "";
        if (username.Length == 0 || string.IsNullOrEmpty(password)) return new(null, "Username or password is empty");

        var lockKey = $"lock:{ip}:{username.ToLowerInvariant()}";
        if (cache.TryGetValue(lockKey, out int fails) && fails >= MaxFailures)
            return new(null, "Too many failed attempts, try again later");

        var lower = username.ToLowerInvariant();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Name.ToLower() == lower || (u.Email != null && u.Email.ToLower() == lower));

        var ok = false;
        if (user is not null && user.ThirdAuthType is null)
        {
            ok = VerifyPassword(user, password);
            if (ok && Hasher.VerifyHashedPassword(user, user.PasswordHash!, password) == PasswordVerificationResult.SuccessRehashNeeded)
                user.PasswordHash = HashPassword(user, password);
        }
        else if (user is null || user.ThirdAuthType == "ldap")
        {
            var lu = await ldap.AuthenticateAsync(username, password);
            if (lu is not null)
            {
                if (user is null)
                {
                    var existing = await db.Users.FirstOrDefaultAsync(u => u.Name.ToLower() == lu.Username.ToLower());
                    if (existing is not null && existing.ThirdAuthType != "ldap")
                        return new(null, "A local account with this name already exists");
                    user = existing;
                }
                if (user is null)
                {
                    if (!await settings.GetBoolAsync(SettingKeys.LdapAutoRegister, true))
                        return new(null, "User not registered");
                    user = new User { Name = lu.Username, ThirdAuthType = "ldap" };
                    db.Users.Add(user);
                }
                user.Email = lu.Email ?? user.Email;
                user.DisplayName = lu.DisplayName ?? user.DisplayName;
                if (!string.IsNullOrEmpty(await settings.GetAsync(SettingKeys.LdapAdminGroupDn))) user.IsAdmin = lu.IsAdmin;
                ok = true;
            }
        }

        if (!ok)
        {
            cache.Set(lockKey, fails + 1, LockWindow);
            log.LogInformation("Failed login for {User} from {Ip}", username, ip);
            return new(null, "Wrong username or password");
        }
        if (user!.Status == UserStatus.Disabled) return new(null, "User is disabled");
        cache.Remove(lockKey);
        await db.SaveChangesAsync();

        if (user.TotpEnabled && !string.IsNullOrEmpty(user.TotpSecret))
        {
            var challenge = TokenService.NewToken(24);
            cache.Set($"tfa:{challenge}", (user.Id, 0), TimeSpan.FromMinutes(5));
            return new(user, null, NeedsTfa: true, TfaChallenge: challenge);
        }
        return new(user, null);
    }

    /// <summary>Second factor for a challenge returned by <see cref="PasswordLoginAsync"/>.</summary>
    public async Task<AuthResult> VerifyTfaAsync(string? challenge, string? code)
    {
        if (string.IsNullOrEmpty(challenge) || !cache.TryGetValue($"tfa:{challenge}", out (int UserId, int Tries) st))
            return new(null, "Verification expired, please log in again");
        var user = await db.Users.FindAsync(st.UserId);
        if (user is null || user.Status != UserStatus.Normal) return new(null, "User is disabled");
        if (!VerifyTotp(user.TotpSecret, code))
        {
            if (st.Tries + 1 >= 5) cache.Remove($"tfa:{challenge}");
            else cache.Set($"tfa:{challenge}", (st.UserId, st.Tries + 1), TimeSpan.FromMinutes(5));
            return new(null, "Wrong verification code");
        }
        cache.Remove($"tfa:{challenge}");
        return new(user, null);
    }

    public static bool VerifyTotp(string? base32Secret, string? code)
    {
        if (string.IsNullOrEmpty(base32Secret) || string.IsNullOrWhiteSpace(code)) return false;
        var totp = new Totp(Base32Encoding.ToBytes(base32Secret));
        return totp.VerifyTotp(code.Trim().Replace(" ", ""), out _, new VerificationWindow(1, 1));
    }

    public static string NewTotpSecret() => Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
}
