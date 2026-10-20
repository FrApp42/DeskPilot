using System.Text;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.EntityFrameworkCore;

namespace DeskPilot.Api;

/// <summary>File downloads for the console (admin cookie required).</summary>
public static class ConsoleDownloads
{
    public static void MapConsoleDownloads(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/console").RequireAuthorization(ConsoleAuth.AdminPolicy);

        g.MapGet("/recordings/{id:int}", async (int id, AppDbContext db, IConfiguration config) =>
        {
            var rec = await db.Recordings.FindAsync(id);
            if (rec is null) return Results.NotFound();
            var dir = AppPaths.Records(config);
            var path = Path.Combine(dir, Path.GetFileName(rec.FileName));
            return File.Exists(path) ? Results.File(path, "application/octet-stream", rec.FileName, enableRangeProcessing: true) : Results.NotFound();
        });

        g.MapGet("/export/conn-audit.csv", async (AppDbContext db) =>
        {
            var rows = await db.ConnAudits.AsNoTracking().OrderByDescending(a => a.Id).Take(50_000).ToListAsync();
            var sb = new StringBuilder("id;device;conn_id;ip;peer_id;peer_name;type;note;created_at;authed_at;closed_at\n");
            foreach (var a in rows)
                sb.AppendLine(string.Join(';', a.Id, a.RustdeskId, a.ConnId, a.Ip, a.PeerId, Csv(a.PeerName), a.Type, Csv(a.Note),
                    a.CreatedAt.ToString("O"), a.AuthedAt?.ToString("O"), a.ClosedAt?.ToString("O")));
            return Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv", "conn-audit.csv");
        });

        g.MapGet("/export/file-audit.csv", async (AppDbContext db) =>
        {
            var rows = await db.FileAudits.AsNoTracking().OrderByDescending(a => a.Id).Take(50_000).ToListAsync();
            var sb = new StringBuilder("id;device;peer_id;conn_id;type;path;is_file;info;created_at\n");
            foreach (var a in rows)
                sb.AppendLine(string.Join(';', a.Id, a.RustdeskId, a.PeerId, a.ConnId, a.Type, Csv(a.Path), a.IsFile, Csv(a.Info), a.CreatedAt.ToString("O")));
            return Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv", "file-audit.csv");
        });
    }

    private static string Csv(string? s) => s is null ? "" : "\"" + s.Replace("\"", "\"\"") + "\"";
}
