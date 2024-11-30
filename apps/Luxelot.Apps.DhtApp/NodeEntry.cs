using System.Collections.Immutable;
using System.Net;

namespace Luxelot.Apps.DhtApp;

public record class NodeEntry : IBucketEntryValue
{
    public required IPEndPoint? RemoteEndpoint { get; init; }

    public required ImmutableArray<byte>? IdentityPublicKey { get; init; }

    public override string ToString() => $"{(IdentityPublicKey == null ? "(NO PUB KEY)" : Convert.ToHexString(IdentityPublicKey.Value.AsSpan())[..8])}... {RemoteEndpoint}";
}