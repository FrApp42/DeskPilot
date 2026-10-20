using DeskPilot.Data;
using Microsoft.EntityFrameworkCore;

namespace DeskPilot.Services;

public static class StartupTasks
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var log = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
        var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await db.Database.MigrateAsync();
                break;
            }
            catch (Exception ex) when (attempt < 15 && ex is Npgsql.NpgsqlException or System.Net.Sockets.SocketException or TimeoutException)
            {
                log.LogWarning("Database not reachable yet ({Message}), retrying...", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }

        if (!await db.Users.AnyAsync())
        {
            var name = config["DeskPilot:AdminUsername"] ?? "admin";
            var password = config["DeskPilot:AdminPassword"];
            var generated = string.IsNullOrEmpty(password);
            if (generated) password = TokenService.NewToken(12);
            var admin = new User { Name = name, DisplayName = "Administrateur", IsAdmin = true };
            admin.PasswordHash = AuthService.HashPassword(admin, password!);
            db.Users.Add(admin);
            await db.SaveChangesAsync();
            if (generated)
                log.LogWarning("Initial admin account created: {User} / {Password} — change this password now.", name, password);
            else
                log.LogInformation("Initial admin account {User} created from configuration.", name);
        }

        // Housekeeping: expired client tokens.
        await db.AccessTokens.Where(t => t.ExpiresAt < DateTime.UtcNow).ExecuteDeleteAsync();
    }
}
