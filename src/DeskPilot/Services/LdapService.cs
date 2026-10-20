using Novell.Directory.Ldap;

namespace DeskPilot.Services;

public record LdapUser(string Username, string? Email, string? DisplayName, bool IsAdmin);

public class LdapService(SettingsService settings, ILogger<LdapService> log)
{
    public Task<bool> IsEnabledAsync() => settings.GetBoolAsync(SettingKeys.LdapEnabled);

    /// <summary>Search-then-bind authentication. Returns null on any failure.</summary>
    public async Task<LdapUser?> AuthenticateAsync(string username, string password)
    {
        if (!await IsEnabledAsync() || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return null;
        try
        {
            using var conn = await ConnectAsync();
            var baseDn = await settings.GetAsync(SettingKeys.LdapBaseDn);
            var filterTpl = await settings.GetAsync(SettingKeys.LdapUserFilter, "(&(objectClass=person)(uid={0}))");
            var uAttr = await settings.GetAsync(SettingKeys.LdapUsernameAttr, "uid");
            var mAttr = await settings.GetAsync(SettingKeys.LdapEmailAttr, "mail");
            var dAttr = await settings.GetAsync(SettingKeys.LdapDisplayNameAttr, "cn");
            var adminGroup = await settings.GetAsync(SettingKeys.LdapAdminGroupDn);

            var filter = string.Format(filterTpl, EscapeFilter(username));
            var results = await conn.SearchAsync(baseDn, LdapConnection.ScopeSub, filter,
                [uAttr, mAttr, dAttr, "memberOf"], false);

            LdapEntry? entry = null;
            while (await results.HasMoreAsync())
            {
                try
                {
                    entry = await results.NextAsync();
                    break;
                }
                catch (LdapReferralException) { }
            }
            if (entry is null) return null;

            // Verify the password by binding as the user.
            using (var userConn = await ConnectAsync(bindAsService: false))
                await userConn.BindAsync(entry.Dn, password);

            var attrs = entry.GetAttributeSet();
            string? Attr(string name) => attrs.ContainsKey(name) ? attrs.GetAttribute(name).StringValue : null;
            var isAdmin = false;
            if (!string.IsNullOrEmpty(adminGroup) && attrs.ContainsKey("memberOf"))
                isAdmin = attrs.GetAttribute("memberOf").StringValueArray
                    .Any(g => string.Equals(g, adminGroup, StringComparison.OrdinalIgnoreCase));

            return new LdapUser(Attr(uAttr) ?? username, Attr(mAttr), Attr(dAttr), isAdmin);
        }
        catch (LdapException ex)
        {
            log.LogInformation("LDAP authentication failed for {User}: {Message}", username, ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "LDAP error");
            return null;
        }
    }

    public async Task<string> TestAsync()
    {
        try
        {
            using var conn = await ConnectAsync();
            return conn.Bound ? "OK : connexion et bind réussis." : "Connecté (bind anonyme).";
        }
        catch (Exception ex)
        {
            return "Échec : " + ex.Message;
        }
    }

    private async Task<LdapConnection> ConnectAsync(bool bindAsService = true)
    {
        var host = await settings.GetAsync(SettingKeys.LdapHost);
        var ssl = await settings.GetBoolAsync(SettingKeys.LdapUseSsl);
        var port = await settings.GetIntAsync(SettingKeys.LdapPort, ssl ? 636 : 389);
        var startTls = await settings.GetBoolAsync(SettingKeys.LdapStartTls);

        var conn = new LdapConnection(ssl ? new LdapConnectionOptions().UseSsl() : new LdapConnectionOptions()) { ConnectionTimeout = 5000 };
        await conn.ConnectAsync(host, port);
        if (startTls && !ssl) await conn.StartTlsAsync();
        if (bindAsService)
        {
            var bindDn = await settings.GetAsync(SettingKeys.LdapBindDn);
            if (!string.IsNullOrEmpty(bindDn))
                await conn.BindAsync(bindDn, await settings.GetAsync(SettingKeys.LdapBindPassword));
        }
        return conn;
    }

    private static string EscapeFilter(string s)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var c in s)
            sb.Append(c switch
            {
                '\\' => @"\5c",
                '*' => @"\2a",
                '(' => @"\28",
                ')' => @"\29",
                '\0' => @"\00",
                _ => c.ToString(),
            });
        return sb.ToString();
    }
}
