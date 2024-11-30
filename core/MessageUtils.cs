using System.Security.Cryptography;
using Luxelot.Messages;
using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot;

internal static class MessageUtils
{
    internal static void Dump(this Messages.Envelope envelope, ILogger? logger = null)
    {
        logger?.LogTrace(
         "\r\nNonce={Nonce}" +
         "\r\nCipherTextSHA256={CipherTextSHA256}" +
         "\r\nAD={AssociatedData}" +
         "\r\nTag={Tag}",
         Convert.ToHexString(envelope.Nonce.Span),
         Convert.ToHexString(SHA256.HashData(envelope.Ciphertext.Span)),
         Convert.ToHexString(envelope.AssociatedData.Span),
         Convert.ToHexString(envelope.Tag.Span));

        Console.WriteLine(
            $"\r\nENVELOPE\r\nNonce={Convert.ToHexString(envelope.Nonce.Span)}" +
            $"\r\nCipherTextSHA256={Convert.ToHexString(SHA256.HashData(envelope.Ciphertext.Span))}" +
            $"\r\nAD={Convert.ToHexString(envelope.AssociatedData.Span)}" +
            $"\r\nTag={Convert.ToHexString(envelope.Tag.Span)}");
    }

    internal static void Dump(this DirectedMessage dm, ILogger? logger = null)
    {
        logger?.LogTrace(
         "\r\nsrc={SrcIdentityPublicKeyThumbprint}" +
         "\r\ndst={DstIdentityPublicKeyThumbprint}" +
         "\r\nsig={Signature}",
         Convert.ToHexString(dm.SrcIdentityThumbprint.Span),
         Convert.ToHexString(dm.DstIdentityThumbprint.Span),
         Convert.ToHexString(SHA256.HashData(dm.Signature.Span)));

        Console.WriteLine(
            $"\r\nDIRECTED MESSAGE\r\nsrc={Convert.ToHexString(dm.SrcIdentityThumbprint.Span)}" +
            $"\r\ndst={Convert.ToHexString(dm.DstIdentityThumbprint.Span)}" +
            $"\r\nsigSHA256={Convert.ToHexString(SHA256.HashData(dm.Signature.Span))}");
    }

    internal static bool IsValid(this ForwardedMessage fwd, ILogger? logger = null)
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