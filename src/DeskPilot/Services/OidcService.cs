using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace DeskPilot.Services;

public record OidcEndpoints(string Authorization, string Token, string? UserInfo);

public class OidcService(AppDbContext db, IHttpClientFactory http, IMemoryCache cache, SettingsService settings, TokenService tokens, ILogger<OidcService> log)
{
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);

    public async Task<OidcSession?> StartAsync(string op, ClientDevice? device, bool forConsole, string? returnUrl)
    {
        var provider = await db.OidcProviders.FirstOrDefaultAsync(p => p.Enabled && p.Name == op);
        if (provider is null) return null;
        await db.OidcSessions.Where(s => s.CreatedAt < DateTime.UtcNow - SessionLifetime).ExecuteDeleteAsync();
        var session = new OidcSession
        {
            Code = TokenService.NewToken(24),
            State = TokenService.NewToken(24),
            CodeVerifier = TokenService.NewToken(48),
            Op = provider.Name,
            ClientId = device?.Id,
            ClientUuid = device?.Uuid,
            DeviceOs = device?.Os,
            DeviceType = device?.Type,
            DeviceName = device?.Name,
            ForConsole = forConsole,
            ReturnUrl = returnUrl,
        };
        db.OidcSessions.Add(session);
        await db.SaveChangesAsync();
        return session;
    }

    /// <summary>URL of the identity provider's authorization endpoint for a pending session.</summary>
    public async Task<string?> AuthorizeUrlAsync(string state, string publicUrl)
    {
        var session = await db.OidcSessions.FirstOrDefaultAsync(s => s.State == state && !s.Consumed && s.AuthedAt == null);
        if (session is null || session.CreatedAt < DateTime.UtcNow - SessionLifetime) return null;
        var provider = await db.OidcProviders.FirstOrDefaultAsync(p => p.Name == session.Op && p.Enabled);
        if (provider is null) return null;
        var ep = await DiscoverAsync(provider.Issuer);
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(session.CodeVerifier)));
        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = provider.ClientId,
            ["redirect_uri"] = publicUrl + "/oidc/callback",
            ["scope"] = provider.Scopes,
            ["state"] = session.State,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["nonce"] = TokenService.NewToken(16),
        };
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(ep.Authorization, query);
    }

    /// <summary>Exchanges the authorization code and resolves (or creates) the local user.</summary>
    public async Task<(OidcSession? Session, User? User, string? Error)> CompleteAsync(string state, string code, string publicUrl)
    {
        var session = await db.OidcSessions.FirstOrDefaultAsync(s => s.State == state && !s.Consumed && s.AuthedAt == null);
        if (session is null || session.CreatedAt < DateTime.UtcNow - SessionLifetime) return (null, null, "Login session expired");
        var provider = await db.OidcProviders.FirstOrDefaultAsync(p => p.Name == session.Op && p.Enabled);
        if (provider is null) return Fail(session, "Provider disabled");

        try
        {
            var ep = await DiscoverAsync(provider.Issuer);
            var client = http.CreateClient("oidc");
            var tokenRsp = await client.PostAsync(ep.Token, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = publicUrl + "/oidc/callback",
                ["client_id"] = provider.ClientId,
                ["client_secret"] = provider.ClientSecret ?? "",
                ["code_verifier"] = session.CodeVerifier,
            }));
            var tokenJson = JsonNode.Parse(await tokenRsp.Content.ReadAsStringAsync()) as JsonObject;
            var accessToken = tokenJson?["access_token"]?.GetValue<string>();
            if (!tokenRsp.IsSuccessStatusCode || accessToken is null)
                return Fail(session, "Token exchange failed: " + (tokenJson?["error_description"] ?? tokenJson?["error"])?.ToString());

            // Claims come from the userinfo endpoint over TLS with the fresh access token,
            // falling back to the id_token payload (received directly from the token endpoint).
            JsonObject claims = new();
            if (ep.UserInfo is not null)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, ep.UserInfo);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var ui = await client.SendAsync(req);
                if (ui.IsSuccessStatusCode) claims = JsonNode.Parse(await ui.Content.ReadAsStringAsync()) as JsonObject ?? new();
            }
            if (claims["sub"] is null && tokenJson?["id_token"]?.GetValue<string>() is { } idToken)
                claims = DecodeJwtPayload(idToken) ?? claims;

            var sub = claims["sub"]?.ToString();
            if (string.IsNullOrEmpty(sub)) return Fail(session, "Identity provider returned no subject");
            var email = claims["email"]?.ToString();
            var emailVerified = claims["email_verified"]?.GetValueKind() == JsonValueKind.True
                                || claims["email_verified"]?.ToString() == "true";
            var username = claims[provider.UsernameClaim]?.ToString()
                           ?? claims["preferred_username"]?.ToString()
                           ?? email?.Split('@')[0]
                           ?? sub;
            var displayName = claims["name"]?.ToString();
            var link = $"{provider.Name}|{sub}";

            var user = await db.Users.FirstOrDefaultAsync(u => u.OidcSubject == link);
            if (user is null && emailVerified && !string.IsNullOrEmpty(email))
            {
                // Link an existing account only on a provider-verified email.
                user = await db.Users.FirstOrDefaultAsync(u => u.OidcSubject == null && u.Email != null && u.Email.ToLower() == email.ToLower());
                if (user is not null) user.OidcSubject = link;
            }
            if (user is null)
            {
                if (!provider.AutoRegister) return Fail(session, "User not registered");
                var name = username;
                for (var i = 2; await db.Users.AnyAsync(u => u.Name == name); i++) name = $"{username}{i}";
                user = new User { Name = name, Email = email, DisplayName = displayName, ThirdAuthType = "oidc/" + provider.Name, OidcSubject = link };
                db.Users.Add(user);
            }
            if (user.Status != UserStatus.Normal) return Fail(session, "User is disabled");
            if (string.IsNullOrEmpty(user.DisplayName)) user.DisplayName = displayName;
            await db.SaveChangesAsync();

            session.UserId = user.Id;
            session.AuthedAt = DateTime.UtcNow;
            if (!session.ForConsole)
            {
                session.AccessToken = await tokens.IssueAsync(user, new ClientDevice(
                    session.ClientId, session.ClientUuid, session.DeviceOs, session.DeviceType, session.DeviceName, null));
            }
            else
            {
                session.Consumed = true;
            }
            await db.SaveChangesAsync();
            return (session, user, null);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "OIDC login failed for provider {Provider}", provider.Name);
            return Fail(session, "OIDC error: " + ex.Message);
        }
    }

    private (OidcSession?, User?, string?) Fail(OidcSession session, string error)
    {
        session.Error = error;
        db.SaveChanges();
        return (session, null, error);
    }

    public async Task<OidcEndpoints> DiscoverAsync(string issuer)
    {
        var key = "oidc:disco:" + issuer;
        if (cache.TryGetValue(key, out OidcEndpoints? ep) && ep is not null) return ep;
        var client = http.CreateClient("oidc");
        var json = JsonNode.Parse(await client.GetStringAsync(issuer.TrimEnd('/') + "/.well-known/openid-configuration"))!;
        ep = new OidcEndpoints(
            json["authorization_endpoint"]!.GetValue<string>(),
            json["token_endpoint"]!.GetValue<string>(),
            json["userinfo_endpoint"]?.GetValue<string>());
        cache.Set(key, ep, TimeSpan.FromHours(1));
        return ep;
    }

    private static JsonObject? DecodeJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2) return null;
        var p = parts[1].Replace('-', '+').Replace('_', '/');
        p = p.PadRight(p.Length + (4 - p.Length % 4) % 4, '=');
        return JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(p))) as JsonObject;
    }

    private static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public Task<string> PublicUrlAsync(HttpRequest req) => settings.PublicUrlAsync(req);
}
