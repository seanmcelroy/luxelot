using System.Collections;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.DhtApp;

public class KademliaDistributedHashTable(ImmutableArray<byte> nodeIdentitykeyPublicThumbprint) : IEnumerable<IBucketEntryValue>, ICollection<BucketEntry>
{
    // NOTE: https://kelseyc18.github.io/kademlia_vis/lookup/
    // NOTE: https://codethechange.stanford.edu/guides/guide_kademlia.html#key-computer-lookups

    private readonly ImmutableArray<byte> NodeIdentitykeyPublicThumbprint = nodeIdentitykeyPublicThumbprint;

    private readonly Bucket[] Buckets = new Bucket[Constants.TREE_HEIGHT];

    public int Count => Buckets.Sum(b => b == default ? 0 : b.Entries.Count(be => be != default));

    public bool IsReadOnly => false;

    public bool InsertBucketValue(ImmutableArray<byte> nodeThumbprint, ImmutableArray<byte> key, IBucketEntryValue value, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (nodeThumbprint.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(nodeThumbprint), $"Thumbprint should be {Apps.Common.Constants.THUMBPRINT_LEN} bytes long but was {nodeThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");
        if (key.Length != Common.Constants.THUMBPRINT_LEN) // Needs to be true for distance metric
            throw new ArgumentOutOfRangeException(nameof(key), $"Key should be {Apps.Common.Constants.THUMBPRINT_LEN} bytes long but was {nodeThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        if (nodeThumbprint.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(nodeThumbprint));
        if (key.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(key));

        var distance = ByteUtils.GetDistanceMetric([.. nodeThumbprint], key);
        var kbucket = ByteUtils.MapDistanceToBucketNumber(distance, Constants.TREE_HEIGHT );

        var bucket = Buckets[kbucket - 1];
        if (bucket == default)
        {
            bucket = new();
            Buckets[kbucket - 1] = bucket;
        }

        for (int i = 0; i < Constants.K; i++)
        {
            if (bucket!.Entries[i] == default)
            {
                bucket.Entries[i] = new BucketEntry { Key = key, Value = value };
                return true;
            }
        }

        logger?.LogDebug("No space left in k-bucket {BucketNumber} for new key", kbucket);
        return false;
    }

    public bool TryGetValue(ImmutableArray<byte> key, [NotNullWhen(true)] out IBucketEntryValue? value)
    {
        if (key.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(key));

        var distance = ByteUtils.GetDistanceMetric(NodeIdentitykeyPublicThumbprint, key);
        var kbucket = ByteUtils.MapDistanceToBucketNumber(distance, Constants.TREE_HEIGHT);
        if (Buckets[kbucket - 1] == default)
        {
            value = null;
            return false;
        }

        var be = Buckets[kbucket - 1].Entries.FirstOrDefault(e => !e.Key.IsDefault && Enumerable.SequenceEqual(e.Key, key));
        if (be == default)
        {
            value = null;
            return false;
        }

        value = be.Value;
        return true;
    }

    public IEnumerator<IBucketEntryValue> GetEnumerator() => Buckets.Where(b => b != default).SelectMany(b => b.Entries.Where(e => e != default).Select(e => e.Value)).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => Buckets.Where(b => b != default).SelectMany(b => b.Entries.Where(e => e != default).Select(e => e.Value)).GetEnumerator();

    public void Add(BucketEntry item) => _ = InsertBucketValue(NodeIdentitykeyPublicThumbprint, item.Key, item.Value, null);

    public void Clear()
    {
        for (int bi = 0; bi < Buckets.Length; bi++) { Buckets[bi] = null!; }
    }

    public bool Contains(BucketEntry item) => Buckets.Any(b => b.Entries.Any(be => be.Equals(item)));

    public void CopyTo(BucketEntry[] array, int arrayIndex)
    {
        var i = 0;
        foreach (var be in Buckets.Where(b => b != null).SelectMany(b => b.Entries))
        {
            if (be == default)
                continue;

            if (arrayIndex + i > array.Length - 1)
                throw new ArgumentOutOfRangeException(nameof(arrayIndex));
            array[arrayIndex + i] = be;
            i++;
        }
    }

    public bool Remove(BucketEntry item)
    {
        foreach (var bucket in Buckets)
        {
            for (int bei = 0; bei < bucket.Entries.Length; bei++)
                if (bucket.Entries[bei].Equals(item))
                {
                    bucket.Entries[bei] = default;
                    return true;
                }
        }
        return false;
    }

    IEnumerator<BucketEntry> IEnumerable<BucketEntry>.GetEnumerator() => Buckets.Where(b => b != default).SelectMany(b => b.Entries.Where(be => be != default)).GetEnumerator();

    public IEnumerable<BucketEntry> FindClosest(Memory<byte> target, int count) =>
        ((IEnumerable<BucketEntry>)this).Select(be => new
        {
            Entry = be,
            Distance = ByteUtils.GetDistanceMetric(be.Key.AsSpan(), target.Span)

        })
        .OrderBy(x => x.Distance)
        .Take(count)
        .Select(x => x.Entry);
}