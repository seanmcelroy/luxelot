using System.Text;

namespace Luxelot.Apps.Common;

public static class DisplayUtils
{
    private static readonly string[] SizeSuffixes = ["bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];

    public static string ConvertByteCountToRelativeSuffix(ulong value, int decimalPlaces = 1)
    {
        if (decimalPlaces < 0) { throw new ArgumentOutOfRangeException(nameof(decimalPlaces)); }
        if (value == 0) { return string.Format("{0:n" + decimalPlaces + "} bytes", 0); }

        // mag is 0 for bytes, 1 for KB, 2, for MB, etc.
        int mag = (int)Math.Log(value, 1024);

        // 1L << (mag * 10) == 2 ^ (10 * mag) 
        // [i.e. the number of bytes in the unit corresponding to mag]
        decimal adjustedSize = (decimal)value / (1L << (mag * 10));

        // make adjustment when the value is large enough that
        // it would round up to 1000 or more
        if (Math.Round(adjustedSize, decimalPlaces) >= 1000)
        {
            mag += 1;
            adjustedSize /= 1024;
        }

        return string.Format("{0:n" + decimalPlaces + "} {1}",
            adjustedSize,
            SizeSuffixes[mag]);
    }


    public static byte[] HexToBytes(string hex)
    {
        try
        {
            return string.IsNullOrWhiteSpace(hex) ? [] : Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            // Swallow.
            return [];
        }
    }

    public static string UnixFileModeToString(uint mode, bool isDirectory) => UnixFileModeToString((UnixFileMode)mode, isDirectory);
    public static string UnixFileModeToString(this UnixFileMode mode, bool isDirectory)
    {
        StringBuilder sb = new();

        sb.AppendJoin(string.Empty,
            isDirectory ? 'd' : '-'
            , mode.HasFlag(UnixFileMode.UserRead) ? 'r' : '-'
            , mode.HasFlag(UnixFileMode.UserWrite) ? 'w' : '-'
            , mode.HasFlag(UnixFileMode.SetUser)
                ? (mode.HasFlag(UnixFileMode.UserExecute) ? 's' : 'S')
                : (mode.HasFlag(UnixFileMode.UserExecute) ? 'x' : '-')
            , mode.HasFlag(UnixFileMode.GroupRead) ? 'r' : '-'
            , mode.HasFlag(UnixFileMode.GroupWrite) ? 'w' : '-'
            , mode.HasFlag(UnixFileMode.SetGroup)
                ? (mode.HasFlag(UnixFileMode.GroupExecute) ? 's' : 'S')
                : (mode.HasFlag(UnixFileMode.GroupExecute) ? 'x' : '-')
            , mode.HasFlag(UnixFileMode.OtherRead) ? 'r' : '-'
            , mode.HasFlag(UnixFileMode.OtherWrite) ? 'w' : '-'
            , mode.HasFlag(UnixFileMode.StickyBit)
                ? (mode.HasFlag(UnixFileMode.OtherExecute) ? 't' : 'T')
                : (mode.HasFlag(UnixFileMode.OtherExecute) ? 'x' : '-')
            );

        return sb.ToString();
    }

    public static UnixFileMode ApplyUmask(this UnixFileMode mode, uint octalUmask)
    {
        uint iMode = (uint)mode;
        uint umask = ConvertOctalToDecimal(octalUmask);
        uint negated = ~umask;
        uint applied = iMode & negated;
        return (UnixFileMode)applied;
    }

    private static uint ConvertOctalToDecimal(uint octalNumber)
    {
        uint decimalNumber = 0;
        uint BASE = 1;
        uint temp = octalNumber;
        while (temp > 0)
        {
            uint last_digit = temp % 10;
            temp /= 10;
            decimalNumber += last_digit * BASE;
            BASE *= 8;
        }
        return decimalNumber;
    }
}