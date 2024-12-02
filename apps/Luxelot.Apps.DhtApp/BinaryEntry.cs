using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace Luxelot.Apps.DhtApp;

public record class BinaryEntry : IBucketEntryValue
{
    public required ImmutableArray<byte> Bytes { get; init; }

    [JsonIgnore]
    public ulong Length => (ulong)ToByteArray().Length;

    public ImmutableArray<byte> ToByteArray() => Bytes;

    public override string ToString() => $"{Convert.ToHexString([..Bytes])[..8]}... (len={Length})";
}