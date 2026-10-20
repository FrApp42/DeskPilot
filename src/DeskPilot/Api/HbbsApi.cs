using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;
using static DeskPilot.Api.ApiHelpers;

namespace DeskPilot.Api;

/// <summary>Last contact with the DeskPilot hbbs fork, shown in the console.</summary>
public class HbbsStatus
{
    public DateTime? LastSyncAt { get; set; }
    public int Online { get; set; }
    public bool Connected => LastSyncAt is { } t && DateTime.UtcNow - t < TimeSpan.FromSeconds(40);
}

/// <summary>
/// Internal API called by the DeskPilot fork of hbbs (see hbbs/src/deskpilot.rs).
/// Authenticated with the shared secret DeskPilot:HbbsSecret / DESKPILOT_SECRET.
/// </summary>
public static class HbbsApi
{
    public static void MapHbbsApi(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/hbbs").AddEndpointFilter(async (ctx, next) =>
        {
            var config = ctx.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var secret = config["DeskPilot:HbbsSecret"];
            if (string.IsNullOrEmpty(secret)) return Error("hbbs integration is not configured", 503);
            var auth = ctx.HttpContext.Request.Headers.Authorization.ToString();
            var given = auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? auth[7..] : "";
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(given), Encoding.UTF8.GetBytes(secret)))
                return Error("Invalid secret", 401);
            return await next(ctx);
        });

        g.MapPost("/sync", SyncAsync);
        g.MapPost("/connect", ConnectAsync);
        g.MapPost("/change-id", ChangeIdAsync);
    }

    /// <summary>Presence in, policy out. Called every 10 s by hbbs.</summary>
    private static async Task<IResult> SyncAsync(HttpContext ctx, AppDbContext db, SettingsService settings, HbbsStatus status)
    {
        var b = await ReadObjectAsync(ctx.Request);
        var online = b.GetStringList("online") ?? [];
        var removed = b.GetStringList("removed") ?? [];
        var now = DateTime.UtcNow;

        foreach (var chunk in online.Chunk(1000))
        {
            var ids = chunk.ToList();
            await db.Devices.Where(d => ids.Contains(d.RustdeskId)).ExecuteUpdateAsync(s => s.SetProperty(d => d.LastSeenAt, now));
        }
        if (removed.Count > 0)
            await db.IdReleases.Where(r => removed.Contains(r.RustdeskId)).ExecuteDeleteAsync();

        status.LastSyncAt = now;
        status.Online = online.Count;

        var requireDeploy = await settings.GetBoolAsync(SettingKeys.RequireKnownDevice);
        return Ok(new Dictionary<string, object>
        {
            ["require_deploy"] = requireDeploy,
            ["deployed"] = requireDeploy
                ? await db.Devices.Where(d => d.Deployed).Select(d => d.RustdeskId).ToListAsync()
                : new List<string>(),
            ["blocked"] = await db.Devices.Where(d => d.Blocked).Select(d => d.RustdeskId).ToListAsync(),
            ["remove"] = await db.IdReleases.Select(r => r.RustdeskId).Distinct().ToListAsync(),
        });
    }

    /// <summary>
    /// Decides whether a connection attempt relayed by hbbs may proceed. The token is the
    /// controlling client's access token (empty when it is not logged in).
    /// </summary>
    private static async Task<IResult> ConnectAsync(HttpContext ctx, AppDbContext db, SettingsService settings,
        TokenService tokens, AccessService access)
    {
        var b = await ReadObjectAsync(ctx.Request);
        var id = b.GetString("id") ?? "";
        var token = b.GetString("token") ?? "";
        var ip = b.GetString("ip");
        var connType = int.TryParse(b.GetString("conn_type"), out var ct) ? ct : 0;

        var device = await db.Devices.Include(d => d.DeviceGroup).FirstOrDefaultAsync(d => d.RustdeskId == id);
        var (user, _) = token.Length > 0 ? await tokens.ValidateAsync("Bearer " + token) : (null, null);
        if (user is not null)
            user = await db.Users.Include(u => u.UserGroup).FirstAsync(u => u.Id == user.Id);
        var mode = await settings.GetAsync(SettingKeys.AccessMode, "off");

        string? deny = null;
        if (device?.Blocked == true)
            deny = "Cet appareil a été bloqué par l'administrateur.";
        else if (mode is "login" or "groups" && user is null)
            deny = "Connectez-vous à votre compte pour accéder à cet appareil.";
        else if (mode == "groups" && user is { IsAdmin: false } &&
                 (device is null || !await access.AccessibleDevices(user).AnyAsync(d => d.Id == device.Id)))
            deny = "Votre compte n'a pas accès à cet appareil.";

        var permissions = user is { IsAdmin: false, UserGroup: not null }
            ? Permissions.Deny(user.UserGroup.DeniedPermissions)
            : 0UL;
        var decision = new ConnectDecision
        {
            AuditRef = Guid.NewGuid().ToString("N"),
            TargetId = id,
            UserId = user?.Id,
            UserName = user?.Name,
            Ip = ip,
            ConnType = connType,
            Allowed = deny is null,
            Reason = deny,
            Permissions = (long)permissions,
        };
        db.ConnectDecisions.Add(decision);
        await db.SaveChangesAsync();

        if (deny is not null)
            return Ok(new Dictionary<string, object> { ["allow"] = false, ["reason"] = deny });
        return Ok(new Dictionary<string, object>
        {
            ["allow"] = true,
            ["relay"] = device?.DeviceGroup?.RelayServer ?? "",
            ["permissions"] = permissions,
            ["audit_ref"] = decision.AuditRef,
        });
    }

    /// <summary>ID change requested by a client. hbbs has already checked the uuid against its registration.</summary>
    private static async Task<IResult> ChangeIdAsync(HttpContext ctx, AppDbContext db, SettingsService settings)
    {
        var b = await ReadObjectAsync(ctx.Request);
        var oldId = b.GetString("old_id") ?? "";
        var newId = b.GetString("new_id") ?? "";
        var uuid = b.GetString("uuid");
        if (!await settings.GetBoolAsync(SettingKeys.AllowIdChange, true)) return Result("DENIED");

        var existing = await db.Devices.FirstOrDefaultAsync(d => d.RustdeskId == newId);
        if (existing is not null && existing.Uuid is not null && uuid is not null && existing.Uuid != uuid)
            return Result("ID_EXISTS");

        var device = await db.Devices.FirstOrDefaultAsync(d => d.RustdeskId == oldId);
        if (device is { Blocked: true }) return Result("DENIED");
        if (await settings.GetBoolAsync(SettingKeys.RequireKnownDevice) && device is not { Deployed: true })
            return Result("DENIED");

        await using var tx = await db.Database.BeginTransactionAsync();
        if (existing is not null && existing.Id != device?.Id) db.Devices.Remove(existing);
        if (device is not null) device.RustdeskId = newId;
        await db.SaveChangesAsync();
        // Keep address books pointing at the machine.
        await db.AbPeers.Where(p => p.PeerId == oldId && !db.AbPeers.Any(o => o.AddressBookId == p.AddressBookId && o.PeerId == newId))
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.PeerId, newId));
        db.DeviceIdChanges.Add(new DeviceIdChange { DeviceId = device?.Id, OldId = oldId, NewId = newId, Ip = b.GetString("ip") });
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return Result("OK");
    }

    private static IResult Result(string r) => Ok(new Dictionary<string, string> { ["result"] = r });
}
