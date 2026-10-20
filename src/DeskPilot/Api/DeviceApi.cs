using System.Text.Json.Nodes;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;
using static DeskPilot.Api.ApiHelpers;

namespace DeskPilot.Api;

public static class DeviceApi
{
    public static void MapDeviceApi(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/heartbeat", async (HttpContext ctx, DeviceService devices) =>
        {
            var body = await ReadObjectAsync(ctx.Request);
            return Ok(await devices.HeartbeatAsync(body, ctx.ClientIp()));
        });

        app.MapPost("/api/sysinfo", async (HttpContext ctx, DeviceService devices) =>
        {
            var body = await ReadObjectAsync(ctx.Request);
            return Results.Text(await devices.UpsertSysinfoAsync(body, ctx.ClientIp()));
        });

        // Lets the client skip the sysinfo upload when nothing changed on either side.
        app.MapPost("/api/sysinfo_ver", () => Results.Text(DeviceService.SysinfoVersion));

        app.MapGet("/api/users", async (HttpContext ctx, AccessService access) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (current, size) = Paging(ctx.Request);
            var q = access.AccessibleUsers(me).AsNoTracking();
            if (ctx.Request.Query["status"] == "1") q = q.Where(u => u.Status == UserStatus.Normal);
            q = q.OrderBy(u => u.Name);
            var total = await q.CountAsync();
            var users = await q.Skip((current - 1) * size).Take(size).ToListAsync();
            return Ok(new Dictionary<string, object> { ["total"] = total, ["data"] = users.Select(UserPayload).ToList() });
        });

        app.MapGet("/api/peers", async (HttpContext ctx, AccessService access) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (current, size) = Paging(ctx.Request);
            var q = access.AccessibleDevices(me).AsNoTracking()
                .Include(d => d.User).Include(d => d.DeviceGroup)
                .OrderBy(d => d.RustdeskId);
            var total = await q.CountAsync();
            var devices = await q.Skip((current - 1) * size).Take(size).ToListAsync();
            var data = devices.Select(d => new Dictionary<string, object?>
            {
                ["id"] = d.RustdeskId,
                ["info"] = new Dictionary<string, object?>
                {
                    ["username"] = d.Username ?? "",
                    ["os"] = d.Os ?? "",
                    ["device_name"] = d.Hostname ?? "",
                },
                ["status"] = 1,
                ["user"] = d.User?.Name ?? "",
                ["user_name"] = d.User?.Name ?? "",
                ["device_group_name"] = d.DeviceGroup?.Name ?? "",
                ["note"] = d.Note ?? "",
            }).ToList();
            return Ok(new Dictionary<string, object> { ["total"] = total, ["data"] = data });
        });

        app.MapGet("/api/device-group/accessible", async (HttpContext ctx, AccessService access) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (current, size) = Paging(ctx.Request);
            var q = access.AccessibleDeviceGroups(me).AsNoTracking().OrderBy(g => g.Name);
            var total = await q.CountAsync();
            var names = await q.Skip((current - 1) * size).Take(size).Select(g => g.Name).ToListAsync();
            var groups = names.Select(n => new Dictionary<string, object> { ["name"] = n }).ToList();
            return Ok(new Dictionary<string, object> { ["total"] = total, ["data"] = groups });
        });

        // rustdesk --assign --token <api token> --user_name ... (run on the device itself)
        app.MapPost("/api/devices/cli", async (HttpContext ctx, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            if (!me.IsAdmin) return Error("Admin required!");
            var b = await ReadObjectAsync(ctx.Request);
            var id = b.GetString("id");
            if (string.IsNullOrEmpty(id)) return Error("ID is required");
            var device = await db.Devices.FirstOrDefaultAsync(d => d.RustdeskId == id);
            if (device is null)
            {
                device = new Device { RustdeskId = id, Uuid = b.GetString("uuid") };
                db.Devices.Add(device);
            }

            if (b.GetString("user_name") is { } un)
            {
                var u = await db.Users.FirstOrDefaultAsync(x => x.Name == un || x.Email == un);
                if (u is null) return Error($"User {un} not found");
                device.UserId = u.Id;
            }
            if (b.GetString("strategy_name") is { } sn)
            {
                var s = await db.Strategies.FirstOrDefaultAsync(x => x.Name == sn);
                if (s is null) return Error($"Strategy {sn} not found");
                device.StrategyId = s.Id;
            }
            if (b.GetString("device_group_name") is { } gn)
            {
                var g = await db.DeviceGroups.FirstOrDefaultAsync(x => x.Name == gn);
                if (g is null) return Error($"Device group {gn} not found");
                device.DeviceGroupId = g.Id;
            }
            if (b.GetString("note") is { } note) device.Note = note;
            if (b.GetString("device_username") is { } du) device.Username = du;
            if (b.GetString("device_name") is { } dn) device.Hostname = dn;

            if (b.GetString("address_book_name") is { } abn)
            {
                var ab = await db.AddressBooks.FirstOrDefaultAsync(a => !a.IsPersonal && a.Name == abn);
                if (ab is null) return Error($"Address book {abn} not found");
                var peer = await db.AbPeers.FirstOrDefaultAsync(p => p.AddressBookId == ab.Id && p.PeerId == id);
                if (peer is null) db.AbPeers.Add(peer = new AbPeer { AddressBookId = ab.Id, PeerId = id });
                if (b.GetString("address_book_alias") is { } al) peer.Alias = al;
                if (b.GetString("address_book_password") is { } pw) peer.Password = pw;
                if (b.GetString("address_book_note") is { } an) peer.Note = an;
                if (b.GetString("address_book_tag") is { } tag)
                {
                    if (!peer.Tags.Contains(tag)) peer.Tags = [.. peer.Tags, tag];
                    if (!await db.AbTags.AnyAsync(t => t.AddressBookId == ab.Id && t.Name == tag))
                        db.AbTags.Add(new AbTag { AddressBookId = ab.Id, Name = tag, Color = 0xFF2196F3 });
                }
            }
            await db.SaveChangesAsync();
            return Empty();
        });

        // rustdesk --deploy --token <api token> [--id <new id>]
        app.MapPost("/api/devices/deploy", async (HttpContext ctx, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            if (!me.IsAdmin) return Error("Admin required!");
            var b = await ReadObjectAsync(ctx.Request);
            var id = b.GetString("id");
            var uuid = b.GetString("uuid");
            if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(uuid)) return Ok(Result("INVALID_INPUT"));
            var byId = await db.Devices.FirstOrDefaultAsync(d => d.RustdeskId == id);
            if (byId is not null && byId.Uuid is not null && byId.Uuid != uuid) return Ok(Result("ID_TAKEN"));
            var device = byId ?? await db.Devices.FirstOrDefaultAsync(d => d.Uuid == uuid);
            if (device is null) db.Devices.Add(device = new Device());
            device.RustdeskId = id;
            device.Uuid = uuid;
            device.PublicKey = b.GetString("pk");
            device.Deployed = true;
            await db.SaveChangesAsync();
            return Ok(Result("OK"));
        });

        // Side-switch grant registration (Pro). Accepted as-is: relaying is done by hbbs/hbbr.
        app.MapPost("/api/switch-grant", () => Ok(new Dictionary<string, object> { ["accepted"] = true }));
    }

    private static Dictionary<string, string> Result(string r) => new() { ["result"] = r };
}
