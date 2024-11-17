namespace Luxelot.Apps.Common;

public static class DisplayUtils
{
    public static string BytesToHex(IEnumerable<byte>? bytes) =>
    bytes == null ? string.Empty : Convert.ToHexString(bytes.ToArray());

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
}