using System.Numerics;

namespace Luxelot.Apps.Common;

public static class ByteUtils
{
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