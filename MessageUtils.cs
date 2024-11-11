using System.Security.Cryptography;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public static class MessageUtils
{
    public static void Dump(Envelope envelope, ILogger? logger)
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
            $"\r\nNonce={CryptoUtils.BytesToHex(envelope.Nonce.ToByteArray())}" +
            $"\r\nCipherTextSHA256={CryptoUtils.BytesToHex(SHA256.HashData(envelope.Ciphertext.ToByteArray()))}" +
            $"\r\nAD={CryptoUtils.BytesToHex(envelope.AssociatedData.ToByteArray())}" +
            $"\r\nTag={CryptoUtils.BytesToHex(envelope.Tag.ToByteArray())}");
    }
}