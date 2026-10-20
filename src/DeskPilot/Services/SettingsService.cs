using DeskPilot.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace DeskPilot.Services;

public static class SettingKeys
{
    public const string PublicUrl = "general.public_url";
    public const string MaxPeersPerAb = "ab.max_peers";
    public const string AccessTokenDays = "auth.token_days";
    public const string AllowRecordUpload = "record.enabled";
    public const string RequireKnownDevice = "device.require_known";
    /// <summary>off | login | groups</summary>
    public const string AccessMode = "access.mode";
    public const string AllowIdChange = "device.allow_id_change";

    public const string LdapEnabled = "ldap.enabled";
    public const string LdapHost = "ldap.host";
    public const string LdapPort = "ldap.port";
    public const string LdapUseSsl = "ldap.ssl";
    public const string LdapStartTls = "ldap.starttls";
    public const string LdapBindDn = "ldap.bind_dn";
    public const string LdapBindPassword = "ldap.bind_password";
    public const string LdapBaseDn = "ldap.base_dn";
    public const string LdapUserFilter = "ldap.user_filter";
    public const string LdapUsernameAttr = "ldap.attr_username";
    public const string LdapEmailAttr = "ldap.attr_email";
    public const string LdapDisplayNameAttr = "ldap.attr_display_name";
    public const string LdapAdminGroupDn = "ldap.admin_group_dn";
    public const string LdapAutoRegister = "ldap.auto_register";
}

public class SettingsService(IDbContextFactory<AppDbContext> dbFactory, IMemoryCache cache, IConfiguration config)
{
    private const string CacheKey = "settings:all";

    private async Task<Dictionary<string, string>> AllAsync()
    {
        if (cache.TryGetValue(CacheKey, out Dictionary<string, string>? all) && all is not null) return all;
        await using var db = await dbFactory.CreateDbContextAsync();
        all = await db.Settings.AsNoTracking().ToDictionaryAsync(s => s.Key, s => s.Value);
        cache.Set(CacheKey, all, TimeSpan.FromSeconds(5));
        return all;
    }

    public async Task<string> GetAsync(string key, string fallback = "")
    {
        var all = await AllAsync();
        if (all.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v)) return v;
        // Environment / appsettings override, e.g. DeskPilot__general.public_url is awkward, so map dots to colons.
        var fromConfig = config[$"DeskPilot:{key.Replace('.', ':')}"];
        return string.IsNullOrEmpty(fromConfig) ? fallback : fromConfig;
    }

    public async Task<bool> GetBoolAsync(string key, bool fallback = false)
    {
        var v = await GetAsync(key);
        return v.Length == 0 ? fallback : v is "1" or "true" or "True" or "Y";
    }

    public async Task<int> GetIntAsync(string key, int fallback)
        => int.TryParse(await GetAsync(key), out var i) ? i : fallback;

    public async Task SetAsync(IDictionary<string, string?> values)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        foreach (var (k, v) in values)
        {
            var s = await db.Settings.FindAsync(k);
            if (s is null) db.Settings.Add(new Setting { Key = k, Value = v ?? "" });
            else s.Value = v ?? "";
        }
        await db.SaveChangesAsync();
        cache.Remove(CacheKey);
    }

    /// <summary>Base URL used for OIDC redirects. Falls back to the incoming request.</summary>
    public async Task<string> PublicUrlAsync(HttpRequest? request)
    {
        var url = await GetAsync(SettingKeys.PublicUrl);
        if (string.IsNullOrWhiteSpace(url) && request is not null)
            url = $"{request.Scheme}://{request.Host}{request.PathBase}";
        return url.TrimEnd('/');
    }
}
