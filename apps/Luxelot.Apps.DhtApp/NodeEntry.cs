using System.Collections.Immutable;
using System.Net;
using Luxelot.Apps.Common;

namespace Luxelot.Apps.DHT;

public record class NodeEntry : IBucketEntryValue
{
    public required IPEndPoint? RemoteEndpoint { get; init; }

    public required ImmutableArray<byte>? IdentityPublicKey { get; init; }

    public override string ToString() => $"{DisplayUtils.BytesToHex(IdentityPublicKey)[..8]}... {RemoteEndpoint}";
}