using System.Collections.Immutable;

namespace Luxelot.Apps.DhtApp;

public interface IBucketEntryValue
{
    public ulong Length { get; }

    public ImmutableArray<byte> ToByteArray();
}