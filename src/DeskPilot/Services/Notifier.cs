namespace DeskPilot.Services;

/// <summary>Per-circuit toast messages.</summary>
public class Notifier
{
    public record Item(Guid Id, string Text, bool Error);

    private readonly List<Item> _items = [];
    public IReadOnlyList<Item> Items => _items;
    public event Action? Changed;

    public void Ok(string text) => Push(text, false);
    public void Error(string text) => Push(text, true);

    private void Push(string text, bool error)
    {
        var item = new Item(Guid.NewGuid(), text, error);
        lock (_items) _items.Add(item);
        Changed?.Invoke();
        _ = Task.Delay(error ? 6000 : 3500).ContinueWith(_ =>
        {
            lock (_items) _items.Remove(item);
            Changed?.Invoke();
        });
    }
}
