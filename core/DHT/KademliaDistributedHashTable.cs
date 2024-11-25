using System.Collections;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Luxelot.Apps.Common.DHT;
using Microsoft.Extensions.Logging;

namespace Luxelot.DHT;

public class KademliaDistributedHashTable(ImmutableArray<byte> nodeIdentitykeyPublicThumbprint) : IEnumerable<IBucketEntryValue>, ICollection<BucketEntry>
{
    // NOTE: https://kelseyc18.github.io/kademlia_vis/lookup/
    // NOTE: https://codethechange.stanford.edu/guides/guide_kademlia.html#key-computer-lookups


    private readonly ImmutableArray<byte> NodeIdentitykeyPublicThumbprint = nodeIdentitykeyPublicThumbprint;

    private readonly Bucket[] Buckets = new Bucket[Constants.TREE_HEIGHT];

    public int Count => Buckets.Sum(b => b == default ? 0 : b.Entries.Count(be => be != default));

    public bool IsReadOnly => false;

    private static int MapDistanceToBucketNumber(uint distance, int dhtHeight = Constants.TREE_HEIGHT)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(distance, dhtHeight * (uint)8);

        var distanceBytes = BitConverter.GetBytes(distance);
        var paddedDistance = new byte[dhtHeight / 8];
        Buffer.BlockCopy(distanceBytes, 0, paddedDistance, 0, paddedDistance.Length);
        return MapDistanceToBucketNumber(paddedDistance, dhtHeight);
    }

    public static int MapDistanceToBucketNumber(byte[] distance, int dhtHeight = Constants.TREE_HEIGHT)
    {
        ArgumentNullException.ThrowIfNull(distance);

        // Distance is the XORed difference of two keys, computed by the caller.
        // Higher distances should point to buckets that account for more keyspace
        //   so that more information is retained for 'closer' items.

        var bucketNumber = dhtHeight;
        var ba = new BitArray(distance);
        if (ba.Length != Constants.TREE_HEIGHT)
            throw new ArgumentOutOfRangeException(nameof(distance), $"Distance must be as many bits ({ba.Length}) as the tree height ({dhtHeight}).");

        for (int i = ba.Length - 1; i >= 0; i--)
        {
            if (ba[i])
                return bucketNumber;
            bucketNumber--;
        }
        return 0;
    }

    public static byte[] GetDistanceMetric(IList<byte> key1, IList<byte> key2)
    {
        ArgumentNullException.ThrowIfNull(key1);
        ArgumentNullException.ThrowIfNull(key2);

        var k1c = key1.Count;
        var k2c = key2.Count;

        if (k1c != k2c)
            throw new ArgumentException($"Both keys must be of the same length, but key1 len was {k1c} and key2 len was {k2c}", nameof(key1));

        var result = new byte[k1c];
        for (int i = 0; i < k1c; i++)
            result[i] = (byte)(key1[i] ^ key2[i]);
        return result;
    }

    public static byte[] GetDistanceMetric(ImmutableArray<byte> key1, ImmutableArray<byte> key2)
    {
        ArgumentNullException.ThrowIfNull(key1);
        ArgumentNullException.ThrowIfNull(key2);

        if (key1.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(key1));
        if (key2.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(key2));

        if (key1.Length != key2.Length)
            throw new ArgumentException($"Both keys must be of the same length, but key1 len was {key1.Length} and key2 len was {key2.Length}", nameof(key1));

        var result = new byte[key1.Length];
        for (int i = 0; i < key1.Length; i++)
            result[i] = (byte)(key1[i] ^ key2[i]);
        return result;
    }

    public bool InsertBucketValue(ImmutableArray<byte> nodeKey, ImmutableArray<byte> key, IBucketEntryValue value, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(nodeKey);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);

        if (nodeKey.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(nodeKey));
        if (key.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(key));

        var distance = GetDistanceMetric([.. nodeKey], key);
        var kbucket = MapDistanceToBucketNumber(distance);

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

    public bool TryGetValue(ImmutableArray<byte> nodeKey, ImmutableArray<byte> key, [NotNullWhen(true)] out IBucketEntryValue? value)
    {
        ArgumentNullException.ThrowIfNull(nodeKey);
        ArgumentNullException.ThrowIfNull(key);

        if (nodeKey.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(nodeKey));
        if (key.IsDefault)
            throw new ArgumentException("Cannot pass a defualt instance in for this array", nameof(key));

        var distance = GetDistanceMetric([.. nodeKey], key);
        var kbucket = MapDistanceToBucketNumber(distance);
        if (Buckets[kbucket - 1] == default)
        {
            value = null;
            return false;
        }

        var be = Buckets[kbucket - 1].Entries.FirstOrDefault(e => Enumerable.SequenceEqual(e.Key, key));
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

    public IEnumerable<BucketEntry> FindClosest(IList<byte> target, int count) =>
        ((IEnumerable<BucketEntry>)this).Select(be => new
        {
            Entry = be,
            Distance = GetDistanceMetric(be.Key, target)

        })
        .OrderBy(x => x.Distance)
        .Take(count)
        .Select(x => x.Entry);
}