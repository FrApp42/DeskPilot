using System.Text.Json;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;
using static DeskPilot.Api.ApiHelpers;

namespace DeskPilot.Api;

public static class AddressBookApi
{
    public static void MapAddressBookApi(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/ab/settings", async (HttpContext ctx, SettingsService settings) =>
        {
            if (await AuthUserAsync(ctx) is null) return Unauthorized();
            return Ok(new Dictionary<string, object> { ["max_peer_one_ab"] = await settings.GetIntAsync(SettingKeys.MaxPeersPerAb, 0) });
        });

        app.MapPost("/api/ab/personal", async (HttpContext ctx, AccessService access) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var ab = await access.GetOrCreatePersonalAbAsync(me);
            return Ok(new Dictionary<string, object> { ["guid"] = ab.Guid });
        });

        app.MapPost("/api/ab/shared/profiles", async (HttpContext ctx, AccessService access) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (current, size) = Paging(ctx.Request);
            var all = await access.SharedAddressBooksAsync(me);
            var page = all.Skip((current - 1) * size).Take(size).Select(x => new Dictionary<string, object?>
            {
                ["guid"] = x.Ab.Guid,
                ["name"] = x.Ab.Name,
                ["owner"] = x.Ab.Owner?.Name ?? "",
                ["note"] = x.Ab.Note ?? "",
                ["rule"] = (int)x.Rule,
            });
            return Ok(new Dictionary<string, object> { ["total"] = all.Count, ["data"] = page.ToList() });
        });

        app.MapPost("/api/ab/peers", async (HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, ctx.Request.Query["ab"], ShareRule.Read);
            if (ab is null) return Error(err!);
            var (current, size) = Paging(ctx.Request);
            var q = db.AbPeers.AsNoTracking().Where(p => p.AddressBookId == ab.Id).OrderBy(p => p.Id);
            var total = await q.CountAsync();
            var peers = await q.Skip((current - 1) * size).Take(size).ToListAsync();
            var ids = peers.Select(p => p.PeerId).ToList();
            var known = await db.Devices.AsNoTracking().Where(d => ids.Contains(d.RustdeskId))
                .ToDictionaryAsync(d => d.RustdeskId);
            var data = peers.Select(p => PeerJson(p, ab.IsPersonal, known.GetValueOrDefault(p.PeerId))).ToList();
            return Ok(new Dictionary<string, object> { ["total"] = total, ["data"] = data });
        });

        app.MapPost("/api/ab/tags/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.Read);
            if (ab is null) return Error(err!);
            var tags = await db.AbTags.AsNoTracking().Where(t => t.AddressBookId == ab.Id).OrderBy(t => t.Name).ToListAsync();
            return Ok(tags.Select(t => new Dictionary<string, object> { ["name"] = t.Name, ["color"] = t.Color }).ToList());
        });

        app.MapPost("/api/ab/peer/add/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db, SettingsService settings) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var body = await ReadObjectAsync(ctx.Request);
            var id = body.GetString("id");
            if (string.IsNullOrWhiteSpace(id)) return Error("Peer id is required");
            if (await db.AbPeers.AnyAsync(p => p.AddressBookId == ab.Id && p.PeerId == id))
                return Error($"{id} already exists");
            var max = await settings.GetIntAsync(SettingKeys.MaxPeersPerAb, 0);
            if (max > 0 && await db.AbPeers.CountAsync(p => p.AddressBookId == ab.Id) >= max)
                return Error("exceed_max_devices");
            var peer = new AbPeer { AddressBookId = ab.Id, PeerId = id.Trim() };
            Apply(peer, body, ab.IsPersonal);
            db.AbPeers.Add(peer);
            await EnsureTagsAsync(db, ab.Id, peer.Tags);
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapPut("/api/ab/peer/update/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var body = await ReadObjectAsync(ctx.Request);
            var id = body.GetString("id");
            var peer = await db.AbPeers.FirstOrDefaultAsync(p => p.AddressBookId == ab.Id && p.PeerId == id);
            if (peer is null) return Error("Peer not found");
            Apply(peer, body, ab.IsPersonal);
            await EnsureTagsAsync(db, ab.Id, peer.Tags);
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapDelete("/api/ab/peer/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var ids = StringArray(await ReadJsonAsync(ctx.Request));
            await db.AbPeers.Where(p => p.AddressBookId == ab.Id && ids.Contains(p.PeerId)).ExecuteDeleteAsync();
            return Empty();
        });

        app.MapPost("/api/ab/tag/add/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var body = await ReadObjectAsync(ctx.Request);
            var name = body.GetString("name")?.Trim();
            if (string.IsNullOrEmpty(name)) return Error("Tag name is required");
            var tag = await db.AbTags.FirstOrDefaultAsync(t => t.AddressBookId == ab.Id && t.Name == name);
            if (tag is null) db.AbTags.Add(tag = new AbTag { AddressBookId = ab.Id, Name = name });
            tag.Color = ColorOf(body) ?? tag.Color;
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapPut("/api/ab/tag/rename/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var body = await ReadObjectAsync(ctx.Request);
            var oldName = body.GetString("old");
            var newName = body.GetString("new")?.Trim();
            if (string.IsNullOrEmpty(oldName) || string.IsNullOrEmpty(newName)) return Error("Invalid tag name");
            if (await db.AbTags.AnyAsync(t => t.AddressBookId == ab.Id && t.Name == newName))
                return Error($"Tag {newName} already exists");
            var tag = await db.AbTags.FirstOrDefaultAsync(t => t.AddressBookId == ab.Id && t.Name == oldName);
            if (tag is null) return Error("Tag not found");
            tag.Name = newName;
            var peers = await db.AbPeers.Where(p => p.AddressBookId == ab.Id && p.Tags.Contains(oldName)).ToListAsync();
            foreach (var p in peers) p.Tags = p.Tags.Select(t => t == oldName ? newName : t).Distinct().ToList();
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapPut("/api/ab/tag/update/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var body = await ReadObjectAsync(ctx.Request);
            var name = body.GetString("name");
            var tag = await db.AbTags.FirstOrDefaultAsync(t => t.AddressBookId == ab.Id && t.Name == name);
            if (tag is null) return Error("Tag not found");
            tag.Color = ColorOf(body) ?? tag.Color;
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapDelete("/api/ab/tag/{guid}", async (string guid, HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var (ab, err) = await access.GetAbAsync(me, guid, ShareRule.ReadWrite);
            if (ab is null) return Error(err!);
            var names = StringArray(await ReadJsonAsync(ctx.Request));
            await db.AbTags.Where(t => t.AddressBookId == ab.Id && names.Contains(t.Name)).ExecuteDeleteAsync();
            var peers = await db.AbPeers.Where(p => p.AddressBookId == ab.Id).ToListAsync();
            foreach (var p in peers.Where(p => p.Tags.Any(names.Contains)))
                p.Tags = p.Tags.Where(t => !names.Contains(t)).ToList();
            await db.SaveChangesAsync();
            return Empty();
        });

        // ----- Legacy single address book API (old clients / servers without shared AB support) -----
        app.MapGet("/api/ab", async (HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var ab = await access.GetOrCreatePersonalAbAsync(me);
            var peers = await db.AbPeers.AsNoTracking().Where(p => p.AddressBookId == ab.Id).OrderBy(p => p.Id).ToListAsync();
            var tags = await db.AbTags.AsNoTracking().Where(t => t.AddressBookId == ab.Id).OrderBy(t => t.Name).ToListAsync();
            var data = new Dictionary<string, object>
            {
                ["tags"] = tags.Select(t => t.Name).ToList(),
                ["peers"] = peers.Select(p => PeerJson(p, true, null)).ToList(),
                ["tag_colors"] = JsonSerializer.Serialize(tags.ToDictionary(t => t.Name, t => t.Color)),
            };
            return Ok(new Dictionary<string, object>
            {
                ["data"] = JsonSerializer.Serialize(data, Json),
                ["licensed_devices"] = 0,
            });
        });

        app.MapPost("/api/ab", async (HttpContext ctx, AccessService access, AppDbContext db) =>
        {
            var me = await AuthUserAsync(ctx);
            if (me is null) return Unauthorized();
            var body = await ReadObjectAsync(ctx.Request);
            if (JsonNode.Parse(body.GetString("data") ?? "{}") is not JsonObject data) return Error("Invalid data");
            var ab = await access.GetOrCreatePersonalAbAsync(me);

            await using var tx = await db.Database.BeginTransactionAsync();
            await db.AbPeers.Where(p => p.AddressBookId == ab.Id).ExecuteDeleteAsync();
            await db.AbTags.Where(t => t.AddressBookId == ab.Id).ExecuteDeleteAsync();
            var colors = new Dictionary<string, long>();
            try { colors = JsonSerializer.Deserialize<Dictionary<string, long>>(data.GetString("tag_colors") ?? "{}") ?? new(); }
            catch (JsonException) { }
            foreach (var t in data.GetStringList("tags") ?? [])
                db.AbTags.Add(new AbTag { AddressBookId = ab.Id, Name = t, Color = colors.GetValueOrDefault(t) });
            if (data["peers"] is JsonArray arr)
            {
                var seen = new HashSet<string>();
                foreach (var node in arr.OfType<JsonObject>())
                {
                    var id = node.GetString("id");
                    if (string.IsNullOrEmpty(id) || !seen.Add(id)) continue;
                    var p = new AbPeer { AddressBookId = ab.Id, PeerId = id };
                    Apply(p, node, true);
                    db.AbPeers.Add(p);
                }
            }
            await db.SaveChangesAsync();
            await tx.CommitAsync();
            return Empty();
        });
    }

    private static Dictionary<string, object?> PeerJson(AbPeer p, bool personal, Device? known)
    {
        var json = new Dictionary<string, object?>
        {
            ["id"] = p.PeerId,
            ["username"] = known?.Username ?? p.Username ?? "",
            ["hostname"] = known?.Hostname ?? p.Hostname ?? "",
            ["platform"] = DeviceService.PlatformFromOs(known?.Os) ?? p.Platform ?? "",
            ["alias"] = p.Alias ?? "",
            ["tags"] = p.Tags,
            ["forceAlwaysRelay"] = p.ForceAlwaysRelay ? "true" : "false",
            ["rdpPort"] = p.RdpPort ?? "",
            ["rdpUsername"] = p.RdpUsername ?? "",
            ["note"] = p.Note ?? "",
            ["same_server"] = known is not null,
        };
        if (personal) json["hash"] = p.Hash ?? "";
        else json["password"] = p.Password ?? "";
        return json;
    }

    /// <summary>Partial update: only the fields present in the JSON body are changed.</summary>
    private static void Apply(AbPeer p, JsonObject b, bool personal)
    {
        if (b.ContainsKey("alias")) p.Alias = b.GetString("alias");
        if (b.ContainsKey("username")) p.Username = b.GetString("username");
        if (b.ContainsKey("hostname")) p.Hostname = b.GetString("hostname");
        if (b.ContainsKey("platform")) p.Platform = b.GetString("platform");
        if (b.ContainsKey("note")) p.Note = b.GetString("note");
        if (b.ContainsKey("tags")) p.Tags = (b.GetStringList("tags") ?? []).Distinct().ToList();
        if (b.ContainsKey("forceAlwaysRelay")) p.ForceAlwaysRelay = b.GetBool("forceAlwaysRelay") ?? false;
        if (b.ContainsKey("rdpPort")) p.RdpPort = b.GetString("rdpPort");
        if (b.ContainsKey("rdpUsername")) p.RdpUsername = b.GetString("rdpUsername");
        // Personal books keep the client-side hash, shared books keep a shared password.
        if (personal && b.ContainsKey("hash")) p.Hash = b.GetString("hash");
        if (!personal && b.ContainsKey("password")) p.Password = b.GetString("password");
    }

    private static async Task EnsureTagsAsync(AppDbContext db, int abId, List<string> tags)
    {
        if (tags.Count == 0) return;
        var existing = await db.AbTags.Where(t => t.AddressBookId == abId && tags.Contains(t.Name)).Select(t => t.Name).ToListAsync();
        foreach (var t in tags.Except(existing))
            db.AbTags.Add(new AbTag { AddressBookId = abId, Name = t, Color = 0xFF9E9E9E });
    }

    private static long? ColorOf(JsonObject b)
    {
        var v = b["color"];
        if (v is null) return null;
        return v.GetValueKind() == JsonValueKind.Number ? v.GetValue<long>()
            : long.TryParse(v.ToString(), out var l) ? l : null;
    }

    private static List<string> StringArray(JsonNode? node)
        => node is JsonArray a ? a.Select(n => n?.ToString()).Where(s => s is not null).Select(s => s!).ToList() : [];
}
