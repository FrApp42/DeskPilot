using DeskPilot.Api;
using DeskPilot.Components;
using DeskPilot.Data;
using DeskPilot.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;

// Docker HEALTHCHECK: the runtime image has no curl.
if (args.Contains("--healthcheck"))
{
    var port = Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS")?.Split(';', ',')[0] ?? "8080";
    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        return (await http.GetAsync($"http://127.0.0.1:{port}/healthz")).IsSuccessStatusCode ? 0 : 1;
    }
    catch { return 1; }
}

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? "Host=localhost;Database=deskpilot;Username=postgres;Password=postgres";

builder.Services.AddDbContextFactory<AppDbContext>(o => o.UseNpgsql(connectionString));
builder.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());

builder.Services.AddMemoryCache();
builder.Services.AddHttpClient("oidc", c => c.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddSingleton<SettingsService>();
builder.Services.AddSingleton<LdapService>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AccessService>();
builder.Services.AddScoped<DeviceService>();
builder.Services.AddScoped<OidcService>();
builder.Services.AddScoped<Notifier>();
builder.Services.AddSingleton<HbbsStatus>();

// Cookies must survive container restarts.
var dataDir = AppPaths.Data(builder.Configuration);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")))
    .SetApplicationName("DeskPilot");

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = "deskpilot.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.LoginPath = "/login";
        o.AccessDeniedPath = "/forbidden";
        o.SlidingExpiration = true;
        o.Events.OnValidatePrincipal = async ctx =>
        {
            // Re-check the account on every request so disabling a user or removing admin rights is immediate.
            var id = ctx.Principal?.UserId();
            var factory = ctx.HttpContext.RequestServices.GetRequiredService<IDbContextFactory<AppDbContext>>();
            await using var db = await factory.CreateDbContextAsync();
            var user = id is null ? null : await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
            if (user is null || user.Status != UserStatus.Normal || user.IsAdmin != ctx.Principal!.IsInRole("admin"))
            {
                ctx.RejectPrincipal();
                await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        };
        // API calls must get a status code, never a redirect to the login page.
        o.Events.OnRedirectToLogin = ctx =>
        {
            if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.StatusCode = 401;
            else ctx.Response.Redirect(ctx.RedirectUri);
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(ConsoleAuth.AdminPolicy, p => p.RequireRole("admin"));
builder.Services.AddCascadingAuthenticationState();

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    // Behind Docker networking / a reverse proxy the proxy address is not known in advance.
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
app.UseWhen(ctx => !ctx.Request.Path.StartsWithSegments("/api"),
    a => a.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();

app.MapAuthApi();
app.MapAddressBookApi();
app.MapDeviceApi();
app.MapAuditApi();
app.MapOidcApi();
app.MapHbbsApi();
app.MapAccountEndpoints();
app.MapConsoleDownloads();
app.MapGet("/healthz", () => Results.Text("ok"));

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

if (!EF.IsDesignTime) await StartupTasks.InitializeAsync(app.Services);
await app.RunAsync();
return 0;

public partial class Program;
