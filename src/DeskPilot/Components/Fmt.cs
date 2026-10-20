using System.Globalization;

namespace DeskPilot.Components;

public static class Fmt
{
    private static readonly CultureInfo Fr = CultureInfo.GetCultureInfo("fr-FR");
    private static readonly TimeZoneInfo Tz = ResolveTz();

    private static TimeZoneInfo ResolveTz()
    {
        var id = Environment.GetEnvironmentVariable("TZ");
        try { return string.IsNullOrEmpty(id) ? TimeZoneInfo.Local : TimeZoneInfo.FindSystemTimeZoneById(id); }
        catch { return TimeZoneInfo.Local; }
    }

    public static DateTime Local(DateTime utc) => TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), Tz);

    public static string Date(DateTime? utc) => utc is null ? "—" : Local(utc.Value).ToString("dd/MM/yyyy HH:mm", Fr);

    public static string Ago(DateTime utc)
    {
        var d = DateTime.UtcNow - utc;
        if (d.TotalSeconds < 60) return "à l'instant";
        if (d.TotalMinutes < 60) return $"il y a {(int)d.TotalMinutes} min";
        if (d.TotalHours < 24) return $"il y a {(int)d.TotalHours} h";
        if (d.TotalDays < 30) return $"il y a {(int)d.TotalDays} j";
        return "le " + Local(utc).ToString("dd/MM/yyyy", Fr);
    }

    public static string Duration(DateTime start, DateTime? end)
    {
        var d = (end ?? DateTime.UtcNow) - start;
        if (d.TotalMinutes < 1) return $"{(int)d.TotalSeconds} s";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes} min";
        return $"{(int)d.TotalHours} h {d.Minutes:00}";
    }

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} o",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} Ko",
        < 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024:0.#} Mo",
        _ => $"{bytes / 1024.0 / 1024 / 1024:0.##} Go",
    };

    public static string ConnType(int? t) => t switch
    {
        0 => "Bureau à distance",
        1 => "Transfert de fichiers",
        2 => "Redirection de port",
        3 => "Caméra",
        4 => "Terminal",
        5 => "Bureau à distance (vue)",
        null => "—",
        _ => $"Type {t}",
    };

    /// <summary>rendezvous.proto ConnType, used in authorization decisions.</summary>
    public static string RequestType(int t) => t switch
    {
        0 => "Bureau à distance",
        1 => "Transfert de fichiers",
        2 => "Redirection de port",
        3 => "RDP",
        4 => "Caméra",
        5 => "Terminal",
        _ => $"Type {t}",
    };

    public static string Alarm(int t) => t switch
    {
        0 => "IP hors liste blanche",
        1 => "Plus de 30 tentatives",
        2 => "6 tentatives en 1 minute",
        6 => "Tentatives IPv6 répétées",
        7 => "Terminal : temporisation de connexion",
        8 => "Terminal : connexions simultanées",
        9 => "Violation de périmètre de session",
        10 => "ID hors liste blanche",
        _ => $"Alarme {t}",
    };

    public static string Rule(DeskPilot.Data.ShareRule r) => r switch
    {
        DeskPilot.Data.ShareRule.Read => "Lecture seule",
        DeskPilot.Data.ShareRule.ReadWrite => "Lecture et écriture",
        _ => "Contrôle total",
    };
}
