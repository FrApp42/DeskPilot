namespace DeskPilot.Services;

public static class AppPaths
{
    public static string Data(IConfiguration c) => c["DeskPilot:DataPath"] ?? Path.Combine(AppContext.BaseDirectory, "data");
    public static string Records(IConfiguration c) => c["DeskPilot:RecordsPath"] ?? Path.Combine(Data(c), "records");
}
