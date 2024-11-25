using System.Collections.Immutable;
using System.Net;

namespace Luxelot.Apps.Common.DHT;

public record class NodeEntry : IBucketEntryValue
{
    public required IPEndPoint? RemoteEndpoint { get; init; }

    public required ImmutableArray<byte>? IdentityPublicKey { get; init; }

    public override string ToString()
    {
        return $"{DisplayUtils.BytesToHex(IdentityPublicKey)[..8]}... {RemoteEndpoint}";
    }
}