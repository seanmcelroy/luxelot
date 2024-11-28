using System.Security.Cryptography;
using Luxelot.Messages;
using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public static class MessageUtils
{
    public static void Dump(this Messages.Envelope envelope, ILogger? logger = null)
    {
        logger?.LogTrace(
         "\r\nNonce={Nonce}" +
         "\r\nCipherTextSHA256={CipherTextSHA256}" +
         "\r\nAD={AssociatedData}" +
         "\r\nTag={Tag}",
         DisplayUtils.BytesToHex(envelope.Nonce.ToByteArray()),
         DisplayUtils.BytesToHex(SHA256.HashData(envelope.Ciphertext.ToByteArray())),
         DisplayUtils.BytesToHex(envelope.AssociatedData.ToByteArray()),
         DisplayUtils.BytesToHex(envelope.Tag.ToByteArray()));

        Console.WriteLine(
            $"\r\nENVELOPE\r\nNonce={DisplayUtils.BytesToHex(envelope.Nonce.ToByteArray())}" +
            $"\r\nCipherTextSHA256={DisplayUtils.BytesToHex(SHA256.HashData(envelope.Ciphertext.ToByteArray()))}" +
            $"\r\nAD={DisplayUtils.BytesToHex(envelope.AssociatedData.ToByteArray())}" +
            $"\r\nTag={DisplayUtils.BytesToHex(envelope.Tag.ToByteArray())}");
    }

    public static void Dump(this DirectedMessage dm, ILogger? logger = null)
    {
        logger?.LogTrace(
         "\r\nsrc={SrcIdentityPublicKeyThumbprint}" +
         "\r\ndst={DstIdentityPublicKeyThumbprint}" +
         "\r\nsig={Signature}",
         DisplayUtils.BytesToHex(dm.SrcIdentityThumbprint.ToByteArray()),
         DisplayUtils.BytesToHex(dm.DstIdentityThumbprint.ToByteArray()),
         DisplayUtils.BytesToHex(SHA256.HashData(dm.Signature.ToByteArray())));

        Console.WriteLine(
            $"\r\nDIRECTED MESSAGE\r\nsrc={DisplayUtils.BytesToHex(dm.SrcIdentityThumbprint.ToByteArray())}" +
            $"\r\ndst={DisplayUtils.BytesToHex(dm.DstIdentityThumbprint.ToByteArray())}" +
            $"\r\nsigSHA256={DisplayUtils.BytesToHex(SHA256.HashData(dm.Signature.ToByteArray()))}");
    }

    public static bool IsValid(this ForwardedMessage fwd, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(fwd);

        if (fwd.Ttl < 0)
        {
            logger?.LogWarning("Forwarded message TTL has expired: ForwardId={ForwardId}", fwd.ForwardId);
            return false;
        }

        if (fwd.SrcIdentityThumbprint == null || fwd.SrcIdentityThumbprint.Length != Constants.THUMBPRINT_LEN)
            return false;
        if (fwd.DstIdentityThumbprint == null || fwd.DstIdentityThumbprint.Length != Constants.THUMBPRINT_LEN)
            return false;
        if (fwd.DstIdentityThumbprint.All(b => b == 0x00))
            return false; // We do not accept forwarded messages destined for loopback
        if (fwd.Signature == null || fwd.Signature.Length != Constants.DILITHIUM_SIG_LEN)
            return false;

        return true;
    }
}