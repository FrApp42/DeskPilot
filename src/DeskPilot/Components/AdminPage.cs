using System.Security.Claims;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.EntityFrameworkCore;

namespace DeskPilot.Components;

/// <summary>Base for interactive console pages: short-lived DbContexts, toasts and the console audit log.</summary>
public abstract class AdminPage : ComponentBase
{
    [Inject] protected IDbContextFactory<AppDbContext> DbFactory { get; set; } = default!;
    [Inject] protected Notifier Notify { get; set; } = default!;
    [Inject] protected AuthenticationStateProvider AuthState { get; set; } = default!;

    protected ClaimsPrincipal Principal { get; private set; } = new();
    protected int? MyId => Principal.UserId();
    protected string Actor => Principal.Identity?.Name ?? "?";

    protected override async Task OnInitializedAsync()
    {
        Principal = (await AuthState.GetAuthenticationStateAsync()).User;
        await LoadAsync();
    }

    protected virtual Task LoadAsync() => Task.CompletedTask;

    protected async Task LogAsync(AppDbContext db, string action, string? target = null)
    {
        db.ConsoleAudits.Add(new ConsoleAudit { Actor = Actor, Action = action, Target = target });
        await db.SaveChangesAsync();
    }

    /// <summary>Runs a change, reports success or the database error as a toast.</summary>
    protected async Task<bool> SaveAsync(Func<AppDbContext, Task> work, string okMessage, string action, string? target = null)
    {
        try
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            await work(db);
            await db.SaveChangesAsync();
            await LogAsync(db, action, target);
            Notify.Ok(okMessage);
            return true;
        }
        catch (DbUpdateException ex) when (ex.InnerException is Npgsql.PostgresException { SqlState: "23505" })
        {
            Notify.Error("Ce nom est déjà utilisé.");
        }
        catch (Exception ex)
        {
            Notify.Error("Échec : " + (ex.InnerException?.Message ?? ex.Message));
        }
        return false;
    }
}
