using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json.Serialization;

namespace Luxelot.Apps.DhtApp;

public record class NodeEntry : IBucketEntryValue
{
    public required IPEndPoint? RemoteEndpoint { get; init; }

    public required ImmutableArray<byte>? IdentityPublicKey { get; init; }

    [JsonIgnore]
    public ulong Length => (ulong)ToByteArray().Length;

    public ImmutableArray<byte> ToByteArray()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(this);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        return [.. jsonBytes];
    }

    public override string ToString() => $"{(IdentityPublicKey == null ? "(NO PUB KEY)" : Convert.ToHexString(IdentityPublicKey.Value.AsSpan())[..8])}... {RemoteEndpoint}";
}