using System.Text;
using Luxelot.Apps.Common;
using Luxelot.Apps.DHT.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.DHT;

public class EntriesCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string FullCommand => "dhtentries";

    public string InteractiveCommand => "entries";

    public string[] InteractiveAliases => [];

    public string ShortHelp => "Lists the current entries in distributed hash tables.  If no DHT is specified, the Node DHT is enumerated";

    public string Usage => "entries [DHT_NUMBER]";

    public string Example => "entries (OR) entries 1";


    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<(bool success, string? errorMessage)> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 1 && words.Length != 2)
            return (false, "Command requires zero or one argument, the optional directory to list.");

        var dhtTableType = DhtTableType.Node;
        if (words.Length == 2 && int.TryParse(words[1], out int i) && Enum.GetValues<DhtTableType>().Select(t => (int)t).Contains(i))
            dhtTableType = (DhtTableType)i;

        if (!appContext.TryGetSingleton(out DhtServerApp? dhtServerApp)
            || dhtServerApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for DHT server");
            return (false, "Internal error.");
        }

        var dht = dhtServerApp.Tables[dhtTableType];

        var sb = new StringBuilder();
        sb.AppendLine("\r\nDHT Entry List");

        var dhtEntries = ((ICollection<BucketEntry>)dht).ToArray();
        if (dhtEntries.Length > 0)
        {
            var dht_key_len = dhtEntries.Max(be => DisplayUtils.BytesToHex(be.Key)[..8].Length);
            sb.AppendLine($"{"DhtKey".PadRight(dht_key_len)} DhtEntry");

            foreach (var bucketEntry in dhtEntries)
            {
                sb.AppendLine($"{DisplayUtils.BytesToHex(bucketEntry.Key)[..8]} {bucketEntry.Value}");
            }
        }
        sb.AppendLine("End of DHT Entry List");
        await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
        return (true, null);
    }
}