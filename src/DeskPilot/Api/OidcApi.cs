using System.Net;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;
using static DeskPilot.Api.ApiHelpers;

namespace DeskPilot.Api;

public static class OidcApi
{
    public static void MapOidcApi(this IEndpointRouteBuilder app)
    {
        // Client: step 1 — returns { code, url }. The client opens url in a browser and polls auth-query with code.
        app.MapPost("/api/oidc/auth", async (HttpContext ctx, OidcService oidc) =>
        {
            var b = await ReadObjectAsync(ctx.Request);
            var op = b.GetString("op") ?? "";
            var session = await oidc.StartAsync(op, AuthApi.DeviceOf(b, ctx), forConsole: false, returnUrl: null);
            if (session is null) return Error($"Unknown login provider: {op}");
            var publicUrl = await oidc.PublicUrlAsync(ctx.Request);
            return Ok(new Dictionary<string, string>
            {
                ["code"] = session.Code,
                ["url"] = $"{publicUrl}/oidc/start/{session.State}",
            });
        });

        // Client: step 2 — polled every second until the browser flow completes.
        app.MapGet("/api/oidc/auth-query", async (string? code, string? uuid, AppDbContext db) =>
        {
            if (string.IsNullOrEmpty(code)) return Error("code is required");
            var s = await db.OidcSessions.FirstOrDefaultAsync(x => x.Code == code && !x.ForConsole);
            if (s is null || s.CreatedAt < DateTime.UtcNow - OidcService.SessionLifetime) return Error("Login session expired");
            if (!string.IsNullOrEmpty(s.ClientUuid) && s.ClientUuid != uuid) return Error("Login session mismatch");
            if (s.Error is not null) return Error(s.Error);
            if (s.Consumed || s.AccessToken is null || s.UserId is null) return Error("No authed oidc is found");

            var user = await db.Users.FindAsync(s.UserId.Value);
            if (user is null) return Error("User not found");
            var token = s.AccessToken;
            s.AccessToken = null;
            s.Consumed = true;
            await db.SaveChangesAsync();
            return Ok(new Dictionary<string, object?>
            {
                ["type"] = "access_token",
                ["access_token"] = token,
                ["user"] = UserPayload(user),
            });
        });

        // Browser: redirect to the identity provider.
        app.MapGet("/oidc/start/{state}", async (string state, HttpContext ctx, OidcService oidc) =>
        {
            var url = await oidc.AuthorizeUrlAsync(state, await oidc.PublicUrlAsync(ctx.Request));
            return url is null ? Page("Lien expiré", "Cette demande de connexion a expiré. Relancez la connexion depuis le client.", false) : Results.Redirect(url);
        });

        // Console: "Sign in with <provider>".
        app.MapGet("/account/oidc/{op}", async (string op, string? returnUrl, OidcService oidc) =>
        {
            var session = await oidc.StartAsync(op, null, forConsole: true, ConsoleAuth.SafeReturnUrl(returnUrl));
            return session is null ? Results.Redirect("/login?error=provider") : Results.Redirect($"/oidc/start/{session.State}");
        });

        app.MapGet("/oidc/callback", async (string? state, string? code, string? error, string? error_description, HttpContext ctx, OidcService oidc) =>
        {
            if (!string.IsNullOrEmpty(error)) return Page("Connexion refusée", error_description ?? error, false);
            if (string.IsNullOrEmpty(state) || string.IsNullOrEmpty(code)) return Page("Requête invalide", "Paramètres manquants.", false);
            var (session, user, err) = await oidc.CompleteAsync(state, code, await oidc.PublicUrlAsync(ctx.Request));
            if (user is null || session is null) return Page("Échec de la connexion", err ?? "Erreur inconnue", false);
            if (session.ForConsole)
            {
                await ConsoleAuth.SignInAsync(ctx, user);
                return Results.Redirect(ConsoleAuth.SafeReturnUrl(session.ReturnUrl));
            }
            return Page("Connexion réussie", $"Connecté en tant que {user.DisplayNameOrName}. Vous pouvez fermer cette page et revenir dans RustDesk.", true);
        });
    }

    private static IResult Page(string title, string message, bool ok)
    {
        var t = WebUtility.HtmlEncode(title);
        var m = WebUtility.HtmlEncode(message);
        var color = ok ? "#1f9d55" : "#c53030";
        return Results.Content($$"""
            <!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{{t}}</title><style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f4f5f7;color:#1a202c}
            main{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:28rem;text-align:center}
            h1{font-size:1.25rem;color:{{color}};margin:0 0 .75rem}p{margin:0;line-height:1.5}</style></head>
            <body><main><h1>{{t}}</h1><p>{{m}}</p></main></body></html>
            """, "text/html; charset=utf-8");
    }
}
