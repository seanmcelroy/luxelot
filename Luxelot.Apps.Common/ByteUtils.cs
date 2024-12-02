using System.Collections;
using System.Collections.Immutable;

namespace Luxelot.Apps.Common;

public static class ByteUtils
{
    public static byte[] GetDistanceMetric(ReadOnlySpan<byte> key1, ReadOnlySpan<byte> key2)
    {
        var k1c = key1.Length;
        var k2c = key2.Length;

        if (k1c != k2c)
            throw new ArgumentException($"Both keys must be of the same length, but key1 len was {k1c} and key2 len was {k2c}", nameof(key1));

        var result = new byte[k1c];
        for (int i = 0; i < k1c; i++)
            result[i] = (byte)(key1[i] ^ key2[i]);
        return result;
    }

    public static byte[] GetDistanceMetric(ImmutableArray<byte> key1, ImmutableArray<byte> key2)
    {
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


    private static int MapDistanceToBucketNumber(uint distance, int dhtHeight)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(distance, dhtHeight * (uint)8);

        var distanceBytes = BitConverter.GetBytes(distance);
        var paddedDistance = new byte[dhtHeight / 8];
        Buffer.BlockCopy(distanceBytes, 0, paddedDistance, 0, paddedDistance.Length);
        return MapDistanceToBucketNumber(paddedDistance, dhtHeight);
    }

    public static int MapDistanceToBucketNumber(byte[] distance, int dhtHeight)
    {
        ArgumentNullException.ThrowIfNull(distance);

        // Distance is the XORed difference of two keys, computed by the caller.
        // Higher distances should point to buckets that account for more keyspace
        //   so that more information is retained for 'closer' items.

        var bucketNumber = dhtHeight;
        var ba = new BitArray(distance);
        if (ba.Length != dhtHeight)
            throw new ArgumentOutOfRangeException(nameof(distance), $"Distance must be as many bits ({ba.Length}) as the tree height ({dhtHeight}).");

        for (int i = ba.Length - 1; i >= 0; i--)
        {
            if (ba[i])
                return bucketNumber;
            bucketNumber--;
        }
        return 0;
    }


    public static int LongestCommonPrefixLength(byte x, byte y)
    {
        int c = x ^ y;
        int result = -1;
        while ((++result < sizeof(byte) * 8) && ((c & 0x80) == 0))
            c <<= 1;
        return result;
    }

    public static int LongestCommonPrefixLength(ushort x, ushort y)
    {
        int c = x ^ y;
        int result = -1;
        while ((++result < sizeof(ushort) * 8) && ((c & 0x8000) == 0))
            c <<= 1;
        return result;
    }

    public static int LongestCommonPrefixLength(uint x, uint y)
    {
        long c = x ^ y;
        int result = -1;
        while ((++result < sizeof(uint) * 8) && ((c & 0x80000000) == 0))
            c <<= 1;
        return result;
    }

    public static int LongestCommonPrefixLength(ulong x, ulong y)
    {
        ulong c = x ^ y;
        int result = -1;
        while ((++result < sizeof(ulong) * 8) && ((c & 0x8000000000000000) == 0))
            c <<= 1;
        return result;
    }

    public static int LongestCommonPrefixLength(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        // The first X bytes are common
        var common_bytes = first.CommonPrefixLength(second);
        if (common_bytes == first.Length)
            return first.Length * 8;

        int c = first[common_bytes] ^ second[common_bytes];
        int result = -1;
        while ((++result < sizeof(byte) * 8) && ((c & 0x80) == 0))
            c <<= 1;
        return (common_bytes * 8) + result;
    }
}