using System.Text.Json;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using Microsoft.EntityFrameworkCore;

namespace DeskPilot.Services;

public class DeviceService(AppDbContext db, SettingsService settings, ILogger<DeviceService> log)
{
    /// <summary>Server-side sysinfo version. Bumping it forces every client to re-upload its sysinfo.</summary>
    public const string SysinfoVersion = "1";

    private static string? Str(JsonObject o, string key)
    {
        var v = o[key];
        if (v is null) return null;
        var s = v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : v.ToJsonString();
        return string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }

    /// <summary>Handles POST /api/sysinfo. Returns the plain-text answer expected by the client.</summary>
    public async Task<string> UpsertSysinfoAsync(JsonObject info, string? ip)
    {
        var id = Str(info, "id");
        if (string.IsNullOrEmpty(id)) return "ID_NOT_FOUND";
        var uuid = Str(info, "uuid");

        var device = await db.Devices.FirstOrDefaultAsync(d => d.RustdeskId == id);
        if (device is null)
        {
            // Same machine re-registered with a new ID: keep its history and assignments.
            if (uuid is not null)
                device = await db.Devices.FirstOrDefaultAsync(d => d.Uuid == uuid);
            if (device is not null)
            {
                log.LogInformation("Device {Old} changed id to {New}", device.RustdeskId, id);
                device.RustdeskId = id;
            }
            else
            {
                // Hardening option: only devices pre-registered with --deploy / --assign are accepted.
                if (await settings.GetBoolAsync(SettingKeys.RequireKnownDevice)) return "ID_NOT_FOUND";
                device = new Device { RustdeskId = id };
                db.Devices.Add(device);
            }
        }

        device.Uuid = uuid ?? device.Uuid;
        device.Hostname = Str(info, "hostname") ?? device.Hostname;
        device.Username = Str(info, "username") ?? device.Username;
        device.Os = Str(info, "os") ?? device.Os;
        device.Cpu = Str(info, "cpu") ?? device.Cpu;
        device.Memory = Str(info, "memory") ?? device.Memory;
        device.Version = Str(info, "version") ?? device.Version;
        device.Ip = ip ?? device.Ip;
        device.SysinfoAt = DateTime.UtcNow;
        device.LastSeenAt = DateTime.UtcNow;
        device.SysinfoJson = info.ToJsonString();

        await ApplyPresetsAsync(device, info);
        await db.SaveChangesAsync();
        return "SYSINFO_UPDATED";
    }

    /// <summary>
    /// Custom-client presets (preset-user-name, preset-strategy-name, ...). They only fill empty
    /// fields so an admin assignment made in the console is never overwritten by the client.
    /// </summary>
    private async Task ApplyPresetsAsync(Device device, JsonObject info)
    {
        var userName = Str(info, "preset-user-name");
        if (userName is not null && device.UserId is null)
            device.UserId = (await db.Users.FirstOrDefaultAsync(u => u.Name == userName || u.Email == userName))?.Id;

        var strategyName = Str(info, "preset-strategy-name");
        if (strategyName is not null && device.StrategyId is null)
            device.StrategyId = (await db.Strategies.FirstOrDefaultAsync(s => s.Name == strategyName))?.Id;

        var groupName = Str(info, "preset-device-group-name");
        if (groupName is not null && device.DeviceGroupId is null)
        {
            var g = await db.DeviceGroups.FirstOrDefaultAsync(x => x.Name == groupName);
            if (g is null)
            {
                g = new DeviceGroup { Name = groupName };
                db.DeviceGroups.Add(g);
            }
            device.DeviceGroup = g;
        }

        var note = Str(info, "preset-note");
        if (note is not null && string.IsNullOrEmpty(device.Note)) device.Note = note;

        var abName = Str(info, "preset-address-book-name");
        if (abName is not null)
        {
            var ab = await db.AddressBooks.FirstOrDefaultAsync(a => !a.IsPersonal && a.Name == abName);
            if (ab is not null && !await db.AbPeers.AnyAsync(p => p.AddressBookId == ab.Id && p.PeerId == device.RustdeskId))
            {
                var tag = Str(info, "preset-address-book-tag");
                if (tag is not null && !await db.AbTags.AnyAsync(t => t.AddressBookId == ab.Id && t.Name == tag))
                    db.AbTags.Add(new AbTag { AddressBookId = ab.Id, Name = tag, Color = 0xFF2196F3 });
                db.AbPeers.Add(new AbPeer
                {
                    AddressBookId = ab.Id,
                    PeerId = device.RustdeskId,
                    Alias = Str(info, "preset-address-book-alias"),
                    Password = Str(info, "preset-address-book-password"),
                    Note = Str(info, "preset-address-book-note"),
                    Hostname = device.Hostname,
                    Username = device.Username,
                    Platform = PlatformFromOs(device.Os),
                    Tags = tag is null ? [] : [tag],
                });
            }
        }
    }

    public static string? PlatformFromOs(string? os)
    {
        if (string.IsNullOrEmpty(os)) return null;
        var first = os.Split(" / ")[0].ToLowerInvariant();
        return first switch
        {
            "windows" => "Windows",
            "macos" => "Mac OS",
            "android" => "Android",
            "linux" => "Linux",
            _ => os.Contains("linux", StringComparison.OrdinalIgnoreCase) ? "Linux" : null,
        };
    }

    /// <summary>Handles POST /api/heartbeat and builds the JSON answer.</summary>
    public async Task<JsonObject> HeartbeatAsync(JsonObject body, string? ip)
    {
        var rsp = new JsonObject();
        var id = Str(body, "id");
        if (string.IsNullOrEmpty(id)) return rsp;

        var device = await db.Devices
            .Include(d => d.Strategy)
            .Include(d => d.User).ThenInclude(u => u!.Strategy)
            .Include(d => d.DeviceGroup).ThenInclude(g => g!.Strategy)
            .FirstOrDefaultAsync(d => d.RustdeskId == id);
        if (device is null)
        {
            // Unknown device: ask the client to (re)upload its sysinfo.
            rsp["sysinfo"] = true;
            return rsp;
        }

        device.LastSeenAt = DateTime.UtcNow;
        device.Ip = ip ?? device.Ip;
        var conns = body["conns"] is JsonArray arr
            ? arr.Select(n => n?.GetValueKind() == JsonValueKind.Number ? n.GetValue<int>() : (int?)null).OfType<int>().ToList()
            : [];
        device.ActiveConns = conns;

        var kicks = await db.PendingDisconnects.Where(p => p.RustdeskId == id).ToListAsync();
        if (kicks.Count > 0)
        {
            var toSend = kicks.Select(k => k.ConnId).Where(conns.Contains).Distinct().ToList();
            if (toSend.Count > 0) rsp["disconnect"] = new JsonArray(toSend.Select(c => (JsonNode)c).ToArray());
            db.PendingDisconnects.RemoveRange(kicks);
        }

        var clientStamp = body["modified_at"]?.GetValueKind() == JsonValueKind.Number ? body["modified_at"]!.GetValue<long>() : 0;
        var strategy = EffectiveStrategy(device);
        var stamp = strategy?.ModifiedAt ?? 0;
        rsp["modified_at"] = stamp;
        if (stamp != clientStamp)
        {
            var options = new JsonObject();
            var applied = strategy?.Options ?? [];
            // Clear options pushed by a previous strategy and no longer present.
            foreach (var k in device.AppliedOptionKeys.Where(k => !applied.ContainsKey(k)))
                options[k] = "";
            foreach (var (k, v) in applied) options[k] = v;
            if (options.Count > 0 || strategy is not null)
                rsp["strategy"] = new JsonObject { ["config_options"] = options };
            device.AppliedOptionKeys = applied.Keys.ToList();
        }

        await db.SaveChangesAsync();
        return rsp;
    }

    /// <summary>Priority: device → owner user → device group.</summary>
    public static Strategy? EffectiveStrategy(Device d)
    {
        foreach (var s in new[] { d.Strategy, d.User?.Strategy, d.DeviceGroup?.Strategy })
            if (s is { Enabled: true }) return s;
        return null;
    }
}
