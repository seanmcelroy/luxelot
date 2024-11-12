using System.Security.Cryptography;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public static class MessageUtils
{
    public static void Dump(this Envelope envelope, ILogger? logger = null)
    {
        logger?.LogTrace(
         "\r\nNonce={Nonce}" +
         "\r\nCipherTextSHA256={CipherTextSHA256}" +
         "\r\nAD={AssociatedData}" +
         "\r\nTag={Tag}",
         CryptoUtils.BytesToHex(envelope.Nonce.ToByteArray()),
         CryptoUtils.BytesToHex(SHA256.HashData(envelope.Ciphertext.ToByteArray())),
         CryptoUtils.BytesToHex(envelope.AssociatedData.ToByteArray()),
         CryptoUtils.BytesToHex(envelope.Tag.ToByteArray()));

        Console.WriteLine(
            $"\r\nENVELOPE\r\nNonce={CryptoUtils.BytesToHex(envelope.Nonce.ToByteArray())}" +
            $"\r\nCipherTextSHA256={CryptoUtils.BytesToHex(SHA256.HashData(envelope.Ciphertext.ToByteArray()))}" +
            $"\r\nAD={CryptoUtils.BytesToHex(envelope.AssociatedData.ToByteArray())}" +
            $"\r\nTag={CryptoUtils.BytesToHex(envelope.Tag.ToByteArray())}");
    }

    public static void Dump(this DirectedMessage dm, ILogger? logger = null)
    {
        logger?.LogTrace(
         "\r\nsrc={SrcIdentityPublicKeyThumbprint}" +
         "\r\ndst={DstIdentityPublicKeyThumbprint}" +
         "\r\nsig={Signature}",
         CryptoUtils.BytesToHex(dm.SrcIdentityThumbprint.ToByteArray()),
         CryptoUtils.BytesToHex(dm.DstIdentityThumbprint.ToByteArray()),
         CryptoUtils.BytesToHex(SHA256.HashData(dm.Signature.ToByteArray())));

        Console.WriteLine(
            $"\r\nDIRECTED MESSAGE\r\nsrc={CryptoUtils.BytesToHex(dm.SrcIdentityThumbprint.ToByteArray())}" +
            $"\r\ndst={CryptoUtils.BytesToHex(dm.DstIdentityThumbprint.ToByteArray())}" +
            $"\r\nsigSHA256={CryptoUtils.BytesToHex(SHA256.HashData(dm.Signature.ToByteArray()))}");
    }

}