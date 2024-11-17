using System.Collections.Immutable;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public readonly struct NodeContext(Node node)
{
    public required readonly string NodeShortName { get; init; }
    public required readonly ImmutableArray<byte> NodeIdentityKeyPublicBytes { get; init; }
    public required readonly ImmutableArray<byte> NodeIdentityKeyPublicThumbprint { get; init; }
    public required readonly ILogger? Logger { get; init; }
    private readonly Node _node = node;

    public IEnumerable<ImmutableArray<byte>> GetNeighborThumbprints() => _node.GetNeighborThumbprints();

    public IMessage? PrepareEnvelopePayload(
        ImmutableArray<byte> routingPeerThumbprint,
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage innerPayload)
    {
        ArgumentNullException.ThrowIfNull(routingPeerThumbprint);
        ArgumentNullException.ThrowIfNull(ultimateDestinationThumbprint);
        ArgumentNullException.ThrowIfNull(innerPayload);

        return _node.PrepareEnvelopePayload(routingPeerThumbprint, ultimateDestinationThumbprint, innerPayload);
    }

    public bool RegisterForwardId(UInt64 forwardId) => _node.RegisterForwardId(forwardId);

    internal void AdvisePeerPathToIdentity(Peer peer, ImmutableArray<byte> thumbprint) {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(thumbprint);

        _node.AdvisePeerPathToIdentity(peer, thumbprint);
    }

    public async Task RelayForwardMessage(ForwardedMessage original, ImmutableArray<byte>? excludedNeighborThumbprint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(original);

        if (excludedNeighborThumbprint != null && excludedNeighborThumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(excludedNeighborThumbprint), $"Thumbprints must be {Constants.THUMBPRINT_LEN} bytes, but the one provided was {excludedNeighborThumbprint.Value.Length} bytes");

        await _node.RelayForwardMessage(original, excludedNeighborThumbprint, Logger, cancellationToken);
    }

    public async Task<(bool handled, bool success)> TryHandleMessage(IRequestContext requestContext, Any message, CancellationToken cancellationToken) => 
        await _node.TryHandleMessage(requestContext, message, cancellationToken);

    public async Task WriteLineToUserAsync(string message, CancellationToken cancellationToken) =>
        await _node.WriteLineToUserAsync(message, cancellationToken);
}