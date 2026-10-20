using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace DeskPilot.Api;

/// <summary>Cookie login for the web console (form posts from the static Login page).</summary>
public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/account/login", async ([FromForm] string? username, [FromForm] string? password, [FromForm] string? returnUrl,
            HttpContext ctx, AuthService auth, AppDbContext db) =>
        {
            var ret = ConsoleAuth.SafeReturnUrl(returnUrl);
            var r = await auth.PasswordLoginAsync(username, password, ctx.Connection.RemoteIpAddress?.ToString());
            if (r.User is null)
                return Results.Redirect($"/login?error={Uri.EscapeDataString(r.Error ?? "")}&returnUrl={Uri.EscapeDataString(ret)}");
            if (r.NeedsTfa)
                return Results.Redirect($"/login?challenge={Uri.EscapeDataString(r.TfaChallenge!)}&returnUrl={Uri.EscapeDataString(ret)}");
            await CompleteAsync(ctx, db, r.User);
            return Results.Redirect(ret);
        });

        app.MapPost("/account/login/2fa", async ([FromForm] string? challenge, [FromForm] string? code, [FromForm] string? returnUrl,
            HttpContext ctx, AuthService auth, AppDbContext db) =>
        {
            var ret = ConsoleAuth.SafeReturnUrl(returnUrl);
            var r = await auth.VerifyTfaAsync(challenge, code);
            if (r.User is null)
            {
                var err = Uri.EscapeDataString(r.Error ?? "");
                return r.Error?.Contains("expired") == true
                    ? Results.Redirect($"/login?error={err}")
                    : Results.Redirect($"/login?challenge={Uri.EscapeDataString(challenge ?? "")}&error={err}&returnUrl={Uri.EscapeDataString(ret)}");
            }
            await CompleteAsync(ctx, db, r.User);
            return Results.Redirect(ret);
        });

        app.MapPost("/account/logout", async (HttpContext ctx) =>
        {
            await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/login");
        });
    }

    private static async Task CompleteAsync(HttpContext ctx, AppDbContext db, User user)
    {
        var tracked = await db.Users.FindAsync(user.Id);
        if (tracked is not null) tracked.LastLoginAt = DateTime.UtcNow;
        db.ConsoleAudits.Add(new ConsoleAudit { Actor = user.Name, Action = "Connexion console", Ip = ctx.Connection.RemoteIpAddress?.ToString() });
        await db.SaveChangesAsync();
        await ConsoleAuth.SignInAsync(ctx, user);
    }
}
