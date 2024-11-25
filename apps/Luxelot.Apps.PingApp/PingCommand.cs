using System.Collections.Immutable;
using Google.Protobuf;
using Luxelot.Apps.Common;
using Luxelot.Apps.PingApp.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.PingApp;

public class PingCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string FullCommand => "ping";

    public string InteractiveCommand => "ping";

    public string[] InteractiveAliases => [];

    public string ShortHelp => "Sends a request for a reply from a remote host";

    public string Usage => "ping [PEER_SHORT_NAME_ROUTE_THROUGH|NODE_ID_THUMBPRINT_ROUTE_THROUGH] <PEER_SHORT_NAME_TO_PING|NODE_ID_THUMBPRINT_TO_PING>";

    public string Example => "ping 00000000";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<bool> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 2 && words.Length != 3)
        {
            await appContext.SendConsoleMessage($"Command requires one or two arguments, the peer short name to direct the ping, and optionally a second parameter which is the THUMBPRINT for the actual intended recipient if different and you want to source route it.", cancellationToken);
            return false;
        }

        var routingPeerShortName = words[1];
        var routingPeerThumbprint = appContext.FindPeerThumbprintByShortName(routingPeerShortName);
        if (routingPeerThumbprint == null)
        {
            await appContext.SendConsoleMessage($"No peer found with name '{routingPeerShortName}'.", cancellationToken);
            return false;
        }

        ImmutableArray<byte>? ultimateDestinationThumbprint = null;
        if (words.Length == 3)
        {
            ultimateDestinationThumbprint = [.. DisplayUtils.HexToBytes(words[2])];
            if (ultimateDestinationThumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            {
                await appContext.SendConsoleMessage($"Invalid THUMBPRINT for the intended recipient.  Thumbprints are {Constants.THUMBPRINT_LEN} bytes.", cancellationToken);
                return false;
            }
        }
        ultimateDestinationThumbprint ??= routingPeerThumbprint;

        var ping = new Ping
        {
            Identifier = 1,
            Sequence = 1,
            Payload = ByteString.Empty
        };

        var success = await appContext.SendRoutedMessage(routingPeerThumbprint.Value, ultimateDestinationThumbprint.Value, ping, cancellationToken);
        if (success)
        {
            var samesies = Enumerable.SequenceEqual(routingPeerThumbprint.Value, ultimateDestinationThumbprint.Value);
            if (samesies)
                appContext.Logger?.LogInformation("PING to {PeerShortName}: {Contents}", routingPeerShortName, $"id={ping.Identifier} seq={ping.Sequence}");
            else
                appContext.Logger?.LogInformation("PING to {PeerShortName} with final destination of {DestinationThumbprint}: {Contents}", routingPeerShortName, DisplayUtils.BytesToHex(ultimateDestinationThumbprint.Value), $"id={ping.Identifier} seq={ping.Sequence}");
        }
        else
        {
            appContext.Logger?.LogError("ERROR sending PING to {PeerShortName}", routingPeerShortName);
        }
        return success;
    }
}