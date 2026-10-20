namespace DeskPilot.Services;

/// <summary>
/// Per-session permissions hbbs can impose on the controlled device (rendezvous.proto
/// ControlPermissions.Permission). Encoded 2 bits per permission: 1 = disabled, 2 = enabled.
/// </summary>
public static class Permissions
{
    public static readonly (string Key, int Index, string Label)[] All =
    [
        ("keyboard", 0, "Clavier et souris"),
        ("clipboard", 2, "Presse-papiers"),
        ("file", 3, "Transfert de fichiers"),
        ("audio", 4, "Audio"),
        ("camera", 5, "Caméra"),
        ("terminal", 6, "Terminal"),
        ("tunnel", 7, "Redirection de port"),
        ("restart", 8, "Redémarrage à distance"),
        ("recording", 9, "Enregistrement de session"),
        ("block_input", 10, "Blocage des entrées locales"),
        ("remote_printer", 1, "Imprimante distante"),
        ("privacy_mode", 12, "Mode confidentialité"),
    ];

    public static ulong Deny(IEnumerable<string> denied)
    {
        ulong bits = 0;
        foreach (var key in denied)
        {
            var p = All.FirstOrDefault(x => x.Key == key);
            if (p.Key is null) continue;
            bits |= 1UL << (p.Index * 2);
        }
        return bits;
    }

    public static IEnumerable<string> Labels(ulong bits)
        => All.Where(p => ((bits >> (p.Index * 2)) & 0b11) == 1).Select(p => p.Label);
}
