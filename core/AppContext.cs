using System.Collections.Immutable;
using Google.Protobuf;
using Luxelot.Apps.Common;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public class AppContext : IAppContext
{
    public required ILogger? Logger { get; init; }

    public required Node Node { private get; init; }

    public ImmutableArray<byte>? FindPeerThumbprintByShortName(string shortName) => Node.FindPeerThumbprintByShortName(shortName);

    private Peer? FindPeerByThumbprint(ImmutableArray<byte> thumbprint) => Node.FindPeerByThumbprint(thumbprint);

    public async Task SendConsoleMessage(string message, CancellationToken cancellationToken)
    {
        await Node.WriteLineToUserAsync(message, cancellationToken);
    }

    public async Task<bool> SendMessage(
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ultimateDestinationThumbprint);
        ArgumentNullException.ThrowIfNull(message);

        var msg = Node.PrepareEnvelopePayload(null, ultimateDestinationThumbprint, message);
        bool success = msg != null;
        if (success)
        {
            var routingPeer = FindPeerByThumbprint(ultimateDestinationThumbprint);
            if (routingPeer != null) {
                // We happen to be directly connected.
                if (msg is ForwardedMessage) {
                    throw new InvalidOperationException();
                }
                var env = routingPeer.PrepareEnvelope(msg!, Logger);
                success = await routingPeer.SendEnvelope(env, Logger, cancellationToken);
            }
            else {
                if (msg is not ForwardedMessage fwd) {
                    throw new InvalidOperationException();
                }

                // TODO: Do we know the best place to send this message?
                // if so, set routingPeer to that and send there.

                // TODO: Otherwise, broadcast to all peers
                await Node.InitiateForwardMessage(fwd, Logger, cancellationToken);
            }

        }

        return success;
    }


    public async Task<bool> SendRoutedMessage(
        ImmutableArray<byte> routingPeerThumbprint,
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(routingPeerThumbprint);
        ArgumentNullException.ThrowIfNull(ultimateDestinationThumbprint);
        ArgumentNullException.ThrowIfNull(message);

        var routingPeer = FindPeerByThumbprint(routingPeerThumbprint) ?? throw new ArgumentOutOfRangeException(nameof(routingPeerThumbprint), $"Unable to find source-routed peer {routingPeerThumbprint} by its thumbprint");
        var msg = Node.PrepareEnvelopePayload(routingPeerThumbprint, ultimateDestinationThumbprint, message);
        bool success = msg != null;
        if (success)
        {
            var env = routingPeer.PrepareEnvelope(msg!, Logger);
            success = await routingPeer.SendEnvelope(env, Logger, cancellationToken);
        }

        return success;
    }
}