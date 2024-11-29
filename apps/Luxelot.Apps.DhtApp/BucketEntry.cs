using System.Collections.Immutable;

namespace Luxelot.Apps.DhtApp;

public readonly record struct BucketEntry
{
    public required ImmutableArray<byte> Key { get; init; }
    public required IBucketEntryValue Value { get; init; }
}