using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DeskPilot.Data;
using DeskPilot.Services;

namespace DeskPilot.Api;

public static class ApiHelpers
{
    /// <summary>Keep property names exactly as written: the client mixes snake_case and camelCase.</summary>
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = null,
        DictionaryKeyPolicy = null,
    };

    public static IResult Ok(object value) => Results.Json(value, Json);

    /// <summary>The RustDesk client treats "200 + empty body" as success for write actions.</summary>
    public static IResult Empty() => Results.Text("", "text/plain", Encoding.UTF8, 200);

    public static IResult Error(string message, int status = 200)
        => Results.Json(new Dictionary<string, string> { ["error"] = message }, Json, statusCode: status);

    public static IResult Unauthorized() => Error("Invalid token", 401);

    public static async Task<JsonNode?> ReadJsonAsync(HttpRequest req)
    {
        if (req.ContentLength == 0) return null;
        using var reader = new StreamReader(req.Body, Encoding.UTF8);
        var text = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return JsonNode.Parse(text); }
        catch (JsonException) { return null; }
    }

    public static async Task<JsonObject> ReadObjectAsync(HttpRequest req)
        => await ReadJsonAsync(req) as JsonObject ?? new JsonObject();

    public static string? GetString(this JsonObject o, string key)
    {
        var v = o[key];
        if (v is null) return null;
        return v.GetValueKind() switch
        {
            JsonValueKind.String => v.GetValue<string>(),
            JsonValueKind.Null => null,
            _ => v.ToJsonString(),
        };
    }

    public static bool? GetBool(this JsonObject o, string key)
    {
        var v = o[key];
        if (v is null) return null;
        return v.GetValueKind() switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => v.GetValue<string>() is "true" or "True" or "1" or "Y",
            _ => null,
        };
    }

    public static List<string>? GetStringList(this JsonObject o, string key)
        => o[key] is JsonArray a ? a.Select(n => n?.ToString()).Where(s => !string.IsNullOrEmpty(s)).Select(s => s!).ToList() : null;

    public static string? ClientIp(this HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString();

    public static (int Current, int PageSize) Paging(HttpRequest req)
    {
        var current = int.TryParse(req.Query["current"], out var c) && c > 0 ? c : 1;
        var size = int.TryParse(req.Query["pageSize"], out var s) && s > 0 ? Math.Min(s, 1000) : 100;
        return (current, size);
    }

    public static async Task<User?> AuthUserAsync(HttpContext ctx)
    {
        var tokens = ctx.RequestServices.GetRequiredService<TokenService>();
        var (user, _) = await tokens.ValidateAsync(ctx.Request.Headers.Authorization);
        return user;
    }

    public static object UserPayload(User u) => new Dictionary<string, object?>
    {
        ["name"] = u.Name,
        ["display_name"] = u.DisplayName ?? "",
        ["avatar"] = "",
        ["email"] = u.Email ?? "",
        ["note"] = u.Note ?? "",
        ["status"] = (int)u.Status,
        ["is_admin"] = u.IsAdmin,
        ["third_auth_type"] = u.ThirdAuthType,
        // The native client requires this object to be present.
        ["info"] = new Dictionary<string, object>
        {
            ["email_verification"] = false,
            ["email_alarm_notification"] = false,
            ["login_device_whitelist"] = Array.Empty<object>(),
            ["other"] = new Dictionary<string, string>(),
        },
    };
}
