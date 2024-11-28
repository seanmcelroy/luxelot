using System.Net;

namespace Luxelot;

internal static class NetUtils
{
    internal static uint[]? ConvertIPAddressToMessageIntegers(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        byte[] addrBytes = new byte[16];
        if (!address.MapToIPv6().TryWriteBytes(addrBytes, out int bytesWritten))
            return null;
        if (bytesWritten != 16)
            throw new InvalidOperationException();

        var addr1 = BitConverter.ToUInt32(addrBytes.AsSpan(0, 4));
        var addr2 = BitConverter.ToUInt32(addrBytes.AsSpan(4, 4));
        var addr3 = BitConverter.ToUInt32(addrBytes.AsSpan(8, 4));
        var addr4 = BitConverter.ToUInt32(addrBytes.AsSpan(12, 4));

        return [addr1, addr2, addr3, addr4];
    }

    internal static IPAddress ConvertMessageIntegersToIPAddress(uint addr1, uint addr2, uint addr3, uint addr4)
    {
        var decodedIpBytes = new byte[16];
        Array.Copy(BitConverter.GetBytes(addr1), 0, decodedIpBytes, 0, 4);
        Array.Copy(BitConverter.GetBytes(addr2), 0, decodedIpBytes, 4, 4);
        Array.Copy(BitConverter.GetBytes(addr3), 0, decodedIpBytes, 8, 4);
        Array.Copy(BitConverter.GetBytes(addr4), 0, decodedIpBytes, 12, 4);
        var decodedAddress = new IPAddress(decodedIpBytes);
        return decodedAddress.IsIPv4MappedToIPv6
            ? decodedAddress.MapToIPv4()
            : decodedAddress;
    }
}