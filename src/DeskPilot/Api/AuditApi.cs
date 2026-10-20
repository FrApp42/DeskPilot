using System.Text.Json;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using static DeskPilot.Api.ApiHelpers;

namespace DeskPilot.Api;

public static class AuditApi
{
    public static void MapAuditApi(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/audit/conn", async (HttpContext ctx, AppDbContext db, IMemoryCache cache) =>
        {
            var b = await ReadObjectAsync(ctx.Request);
            if (IsReplay(b, cache)) return Empty();
            var id = b.GetString("id");
            if (string.IsNullOrEmpty(id)) return Error("id is required");
            var sessionId = b.GetString("session_id");

            // Note written by the controlling side at the end of a session.
            if (b.ContainsKey("note") && !b.ContainsKey("conn_id"))
            {
                var rec = await db.ConnAudits.Where(a => a.RustdeskId == id && a.SessionId == sessionId)
                    .OrderByDescending(a => a.Id).FirstOrDefaultAsync();
                if (rec is not null)
                {
                    rec.Note = b.GetString("note");
                    await db.SaveChangesAsync();
                }
                return Empty();
            }

            var connId = b["conn_id"]?.GetValueKind() == JsonValueKind.Number ? b["conn_id"]!.GetValue<int>() : 0;
            var action = b.GetString("action");
            var open = await db.ConnAudits
                .Where(a => a.RustdeskId == id && a.ConnId == connId && a.ClosedAt == null)
                .OrderByDescending(a => a.Id).FirstOrDefaultAsync();

            if (action == "new" || open is null)
            {
                open = new ConnAudit { RustdeskId = id, ConnId = connId };
                db.ConnAudits.Add(open);
            }
            open.Uuid = b.GetString("uuid") ?? open.Uuid;
            open.SessionId = sessionId ?? open.SessionId;
            if (b.GetString("ip") is { } ip) open.Ip = ip;
            if (b.GetString("conn_audit_ref") is { } aref) open.ConnAuditRef = aref;

            // Authenticated: "peer": [id, name], "type": n
            if (b["peer"] is JsonArray peer)
            {
                open.PeerId = peer.Count > 0 ? peer[0]?.ToString() : null;
                open.PeerName = peer.Count > 1 ? peer[1]?.ToString() : null;
                open.AuthedAt = DateTime.UtcNow;
            }
            if (b["type"]?.GetValueKind() == JsonValueKind.Number) open.Type = b["type"]!.GetValue<int>();
            if (b["primary_auth"]?.GetValueKind() == JsonValueKind.Number) open.PrimaryAuth = b["primary_auth"]!.GetValue<int>();
            if (b["two_factor"]?.GetValueKind() == JsonValueKind.Number) open.TwoFactor = b["two_factor"]!.GetValue<int>();
            if (action == "close") open.ClosedAt = DateTime.UtcNow;

            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapPost("/api/audit/file", async (HttpContext ctx, AppDbContext db, IMemoryCache cache) =>
        {
            var b = await ReadObjectAsync(ctx.Request);
            if (IsReplay(b, cache)) return Empty();
            var id = b.GetString("id");
            if (string.IsNullOrEmpty(id)) return Error("id is required");
            db.FileAudits.Add(new FileAudit
            {
                RustdeskId = id,
                Uuid = b.GetString("uuid"),
                PeerId = b.GetString("peer_id"),
                ConnId = b["conn_id"]?.GetValueKind() == JsonValueKind.Number ? b["conn_id"]!.GetValue<int>() : 0,
                Type = b["type"]?.GetValueKind() == JsonValueKind.Number ? b["type"]!.GetValue<int>() : 0,
                Path = b.GetString("path"),
                IsFile = b.GetBool("is_file") ?? false,
                Info = b.GetString("info"),
            });
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapPost("/api/audit/alarm", async (HttpContext ctx, AppDbContext db, IMemoryCache cache) =>
        {
            var b = await ReadObjectAsync(ctx.Request);
            if (IsReplay(b, cache)) return Empty();
            var id = b.GetString("id");
            if (string.IsNullOrEmpty(id)) return Error("id is required");
            db.AlarmAudits.Add(new AlarmAudit
            {
                RustdeskId = id,
                Uuid = b.GetString("uuid"),
                Typ = b["typ"]?.GetValueKind() == JsonValueKind.Number ? b["typ"]!.GetValue<int>() : -1,
                Info = b.GetString("info"),
                ConnId = b["conn_id"]?.GetValueKind() == JsonValueKind.Number ? b["conn_id"]!.GetValue<int>() : null,
            });
            await db.SaveChangesAsync();
            return Empty();
        });

        app.MapPost("/api/record", HandleRecordAsync);
    }

    /// <summary>The client retries audit posts and tags each record with a nonce; drop duplicates.</summary>
    private static bool IsReplay(JsonObject b, IMemoryCache cache)
    {
        var nonce = b.GetString("nonce");
        if (string.IsNullOrEmpty(nonce)) return false;
        var key = "nonce:" + nonce;
        if (cache.TryGetValue(key, out _)) return true;
        cache.Set(key, true, TimeSpan.FromMinutes(10));
        return false;
    }

    /// <summary>Session recording upload: ?type=new|part|tail|remove&amp;file=..&amp;offset=..&amp;length=..</summary>
    private static async Task<IResult> HandleRecordAsync(HttpContext ctx, AppDbContext db, SettingsService settings, IConfiguration config)
    {
        if (!await settings.GetBoolAsync(SettingKeys.AllowRecordUpload)) return Error("Recording upload is disabled");
        var q = ctx.Request.Query;
        var name = Path.GetFileName(q["file"].ToString());
        if (string.IsNullOrEmpty(name) || name.Contains("..") || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return Error("Invalid file name");
        var dir = AppPaths.Records(config);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        var rec = await db.Recordings.FirstOrDefaultAsync(r => r.FileName == name);

        switch (q["type"].ToString())
        {
            case "new":
                if (rec is null) db.Recordings.Add(rec = new Recording { FileName = name });
                rec.Size = 0;
                rec.Completed = false;
                rec.Ip = ctx.ClientIp();
                await using (File.Create(path)) { }
                break;
            case "part":
            case "tail":
                if (rec is null) return Error("Unknown recording");
                if (!long.TryParse(q["offset"], out var offset) || offset < 0) return Error("Invalid offset");
                await using (var fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read))
                {
                    fs.Seek(offset, SeekOrigin.Begin);
                    await ctx.Request.Body.CopyToAsync(fs);
                    rec.Size = Math.Max(rec.Size, fs.Length);
                }
                if (q["type"] == "tail") rec.Completed = true;
                break;
            case "remove":
                if (File.Exists(path)) File.Delete(path);
                if (rec is not null) db.Recordings.Remove(rec);
                await db.SaveChangesAsync();
                return Empty();
            default:
                return Error("Invalid type");
        }
        rec.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return Empty();
    }
}
