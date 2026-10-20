using DeskPilot.Data;
using Microsoft.EntityFrameworkCore;

namespace DeskPilot.Services;

/// <summary>Visibility rules shared by the client API and the console.</summary>
public class AccessService(AppDbContext db)
{
    /// <summary>Admins see everyone; others see the members of their user group (or only themselves).</summary>
    public IQueryable<User> AccessibleUsers(User me)
    {
        if (me.IsAdmin) return db.Users;
        if (me.UserGroupId is { } gid) return db.Users.Where(u => u.UserGroupId == gid);
        return db.Users.Where(u => u.Id == me.Id);
    }

    public IQueryable<DeviceGroup> AccessibleDeviceGroups(User me)
    {
        if (me.IsAdmin) return db.DeviceGroups;
        var gid = me.UserGroupId;
        return db.DeviceGroups.Where(g => gid != null && g.Accesses.Any(a => a.UserGroupId == gid));
    }

    /// <summary>Devices owned by accessible users, plus devices of device groups granted to the user's group.</summary>
    public IQueryable<Device> AccessibleDevices(User me)
    {
        if (me.IsAdmin) return db.Devices;
        var gid = me.UserGroupId;
        var users = AccessibleUsers(me).Select(u => u.Id);
        return db.Devices.Where(d =>
            (d.UserId != null && users.Contains(d.UserId.Value)) ||
            (gid != null && d.DeviceGroupId != null && d.DeviceGroup!.Accesses.Any(a => a.UserGroupId == gid)));
    }

    /// <summary>Shared (non-personal) address books visible to the user, with the effective rule.</summary>
    public async Task<List<(AddressBook Ab, ShareRule Rule)>> SharedAddressBooksAsync(User me)
    {
        var gid = me.UserGroupId;
        var books = await db.AddressBooks.AsNoTracking()
            .Include(a => a.Owner)
            .Include(a => a.Shares)
            .Where(a => !a.IsPersonal && (a.OwnerId == me.Id ||
                        a.Shares.Any(s => s.UserId == me.Id || (gid != null && s.UserGroupId == gid))))
            .OrderBy(a => a.Name)
            .ToListAsync();
        return books.Select(a => (a, RuleFor(me, a)!.Value)).ToList();
    }

    public static ShareRule? RuleFor(User me, AddressBook ab)
    {
        if (ab.OwnerId == me.Id) return ShareRule.FullControl;
        if (ab.IsPersonal) return null;
        ShareRule? best = null;
        foreach (var s in ab.Shares)
        {
            if (s.UserId == me.Id || (me.UserGroupId is { } g && s.UserGroupId == g))
                if (best is null || s.Rule > best) best = s.Rule;
        }
        return best;
    }

    /// <summary>Loads an address book by guid and checks the caller has at least <paramref name="min"/>.</summary>
    public async Task<(AddressBook? Ab, string? Error)> GetAbAsync(User me, string? guid, ShareRule min)
    {
        if (string.IsNullOrEmpty(guid)) return (null, "Address book guid is required");
        var ab = await db.AddressBooks.Include(a => a.Shares).FirstOrDefaultAsync(a => a.Guid == guid);
        if (ab is null) return (null, "Address book not found");
        var rule = RuleFor(me, ab);
        if (rule is null) return (null, "Address book not found");
        if (rule < min) return (null, "No permission");
        return (ab, null);
    }

    public async Task<AddressBook> GetOrCreatePersonalAbAsync(User me)
    {
        var ab = await db.AddressBooks.FirstOrDefaultAsync(a => a.OwnerId == me.Id && a.IsPersonal);
        if (ab is not null) return ab;
        ab = new AddressBook { Name = "My address book", IsPersonal = true, OwnerId = me.Id };
        db.AddressBooks.Add(ab);
        await db.SaveChangesAsync();
        return ab;
    }
}
