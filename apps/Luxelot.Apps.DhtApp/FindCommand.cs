using System.Collections.Immutable;
using System.Text;
using Luxelot.Apps.Common;
using Luxelot.Apps.DhtApp.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.DhtApp;

public class FindCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string InteractiveCommand => "find";

    public string[] InteractiveAliases => [];

    public string ShortHelp => "Attempts to find the value from the network for a given KEY in a particular DHT_NUMBER table";

    public string Usage => "find <DHT_NUMBER> <KEY>";

    public string Example => "find 0 593EEFC175710C9831AC67C2684508BD9A1627CD14207C696E0949D24C2F2D22";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<(bool success, string? errorMessage)> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 3)
            return (false, "Command requires two arguments, the DHT table to search (0=Node, 1=Binary) and the key to search for.");

        var dhtTableType = DhtTableType.Node;
        if (!int.TryParse(words[1], out int i) || !Enum.GetValues<DhtTableType>().Select(t => (int)t).Contains(i))
            return (false, $"Argument one mjst be the DHT table to search for.  Valid values are {Enum.GetValues<DhtTableType>().Select(t => ((int)t).ToString()).Aggregate((c, n) => c + "," + n)}.");

        if (!appContext.TryGetSingleton(out DhtServerApp? dhtServerApp)
            || dhtServerApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for DHT server");
            return (false, "Internal error.");
        }

        ImmutableArray<byte> key = [.. DisplayUtils.HexToBytes(words[2])];
        if (key == null)
        {
            return (false, $"Unable to parse '{words[2]}' as hexadecimal bytes.");
        }

        if (key.Length * 8 != Constants.BUCKET_ENTRY_KEY_BIT_LENGTH)
        {
            return (false, $"Hash is not the correct bit length of {Constants.BUCKET_ENTRY_KEY_BIT_LENGTH} bits ({Constants.BUCKET_ENTRY_KEY_BIT_LENGTH / 8} bytes).  Hash provided is {key.Length} bytes.");
        }

        // First, search my own table
        var dht = dhtServerApp.Tables[dhtTableType];
        var distance = ByteUtils.GetDistanceMetric(key, appContext.IdentityKeyPublicThumbprint);
        var bucket = ByteUtils.MapDistanceToBucketNumber(distance, Constants.TREE_HEIGHT);

        if (!dht.TryGetValue(key, out IBucketEntryValue? value))
        {
            await appContext.SendConsoleMessage($"No local entry for key (searched bucket {bucket})..", cancellationToken);
        }
        else
        {
            return (true, $"Value found for key '{Convert.ToHexString([.. key])}': {value}");
            throw new NotImplementedException();
        }

        // Next, reach out to the network.

        throw new NotImplementedException();
        return (true, null);
    }
}