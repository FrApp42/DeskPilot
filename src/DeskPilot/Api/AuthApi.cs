using System.Text.Json;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;
using static DeskPilot.Api.ApiHelpers;

namespace DeskPilot.Api;

public static class AuthApi
{
    public static void MapAuthApi(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/login", LoginAsync);

        app.MapPost("/api/logout", async (HttpContext ctx, TokenService tokens) =>
        {
            await tokens.RevokeAsync(ctx.Request.Headers.Authorization);
            return Empty();
        });

        app.MapPost("/api/currentUser", async (HttpContext ctx) =>
        {
            var user = await AuthUserAsync(ctx);
            return user is null ? Unauthorized() : Ok(UserPayload(user));
        });

        // ["oidc/<name>", ...] — the client shows one button per provider.
        app.MapGet("/api/login-options", async (AppDbContext db) =>
        {
            var names = await db.OidcProviders.Where(p => p.Enabled).OrderBy(p => p.Name).Select(p => p.Name).ToListAsync();
            return Ok(names.Select(n => "oidc/" + n).ToList());
        });
    }

    private static async Task<IResult> LoginAsync(HttpContext ctx, AuthService auth, TokenService tokens)
    {
        var body = await ReadObjectAsync(ctx.Request);
        var type = body.GetString("type") ?? "account";
        var device = DeviceOf(body, ctx);

        AuthResult result;
        if (type is "email_code" or "tfa_code" || !string.IsNullOrEmpty(body.GetString("tfaCode")))
        {
            result = await auth.VerifyTfaAsync(body.GetString("secret"), body.GetString("tfaCode") ?? body.GetString("verificationCode"));
        }
        else if (type == "account")
        {
            result = await auth.PasswordLoginAsync(body.GetString("username"), body.GetString("password"), ctx.ClientIp());
            if (result.NeedsTfa)
            {
                // Client expects type=email_check + tfa_type=tfa_check to show the TOTP dialog.
                return Ok(new Dictionary<string, object?>
                {
                    ["type"] = "email_check",
                    ["tfa_type"] = "tfa_check",
                    ["secret"] = result.TfaChallenge,
                    ["user"] = new Dictionary<string, object?> { ["name"] = result.User!.Name },
                });
            }
        }
        else
        {
            return Error("Unsupported login type");
        }

        if (result.User is null) return Error(result.Error ?? "Login failed");

        var token = await tokens.IssueAsync(result.User, device);
        return Ok(new Dictionary<string, object?>
        {
            ["type"] = "access_token",
            ["access_token"] = token,
            ["user"] = UserPayload(result.User),
        });
    }

    public static ClientDevice DeviceOf(JsonObject body, HttpContext ctx)
    {
        var info = body["deviceInfo"] as JsonObject;
        return new ClientDevice(
            body.GetString("id"),
            body.GetString("uuid"),
            info?.GetString("os"),
            info?.GetString("type"),
            info?.GetString("name"),
            ctx.ClientIp());
    }
}
