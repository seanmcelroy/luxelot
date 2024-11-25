using System.Collections.Immutable;
using Luxelot.Apps.Common.DHT;

namespace Luxelot.DHT;

public readonly record struct BucketEntry
{
    public required ImmutableArray<byte> Key { get; init; }
    public required IBucketEntryValue Value { get; init; }
}