using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;

namespace Luxelot;

internal static class CryptoUtils
{
    private static readonly Mutex mutex = new();
    private static readonly SecureRandom SecureRandom = new();

    // ML-KEM (Kyber) - Super helpful: https://stackoverflow.com/questions/75240825/implementing-crystals-kyber-using-bouncycastle-java
    // ML-DSA (Dilithium) - Super helpful: https://asecuritysite.com/bouncy/bc_dil

    internal static AsymmetricCipherKeyPair GenerateDilithiumKeyPair()
    {
        // These keys are used for NODE IDENTITY.  The node can sign envelopes forwarded
        // by other nodes around the network.

        MLDsaKeyGenerationParameters parameters = new(SecureRandom, MLDsaParameters.ml_dsa_87);
        MLDsaKeyPairGenerator gen = new();
        gen.Init(parameters);
        var keyPair = gen.GenerateKeyPair();
        return keyPair;
    }

    internal static (ImmutableArray<byte> publicKeyBytes, ImmutableArray<byte> privateKeyBytes) GenerateKyberKeyPair(ILogger? logger)
    {
        byte[] publicKeyBytes, privateKeyBytes;

        using (logger?.BeginScope($"Crypto setup"))
        {
            // Generate Kyber crypto material for our comms with this peer.
            AsymmetricCipherKeyPair node_key;
            try
            {
                node_key = GenerateKyberKeyPairInternal(logger);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Unable to generate Kyber key pair");
                throw;
            }

            // Generate the encryption key and the encapsulated key
            //var secretKeyWithEncapsulationSender = CryptoUtils.GenerateChrystalsKyberEncryptionKey((KyberPublicKeyParameters)node_key.Public);
            //encryptionKey = secretKeyWithEncapsulationSender.GetSecret();
            //encapsulatedKey = secretKeyWithEncapsulationSender.GetEncapsulation();

            //logger.LogInformation("Encryption side: generate the encryption key and the encapsulated key\r\n"
            //+ $"Encryption key length: {encryptionKey.Length} key: {CryptoUtils.BytesToHex(encryptionKey)}\r\n"
            //+ $"Encapsulated key length: {encapsulatedKey.Length} key: {CryptoUtils.BytesToHex(encapsulatedKey)}");

            privateKeyBytes = GetChrystalsKyberPrivateKeyFromEncoded(node_key);
            //decryptionKey = CryptoUtils.GenerateChrystalsKyberDecryptionKey(privateKeyBytes, encapsulatedKey);
            //var keysAreEqual = Enumerable.SequenceEqual(encryptionKey, decryptionKey);

            //logger.LogInformation("Decryption side: receive the encapsulated key and generate the decryption key\r\n"
            //    + $"Decryption key length: {decryptionKey.Length} key: {CryptoUtils.BytesToHex(decryptionKey)}"
            //    + $"Decryption key is equal to encryption key: {keysAreEqual}");

            //logger?.LogTrace("Generated private key length: {PrivateKeyByteLength}", privateKeyBytes.Length);
            publicKeyBytes = GetChrystalsKyberPublicKeyFromEncoded(node_key);
            //logger?.LogTrace("Generated public key length: {PublicKeyByteLength}", publicKeyBytes.Length);

            logger?.LogDebug("Key pairs successfully generated");
        }

        return (publicKeyBytes.ToImmutableArray(), privateKeyBytes.ToImmutableArray());
    }

    private static AsymmetricCipherKeyPair GenerateKyberKeyPairInternal(ILogger? logger)
    {
        // These keys are used for PEER (neighor across the network) CHANNEL ENCRYPTION.
        // A shared key is established using the Kyber KEM process,
        // and these are not ferried around the network.

        AsymmetricCipherKeyPair key_pair;

        // Exponential backoff
        const int baseBackoff = 100;
        var failcount = 0;
        var backoff = baseBackoff;
        bool okay;
        do
        {
            okay = mutex.WaitOne(backoff);
            if (!okay)
            {
                failcount++;
                backoff = (int)Math.Pow(baseBackoff, failcount + 1);
            }
        } while (!okay);
        logger?.LogTrace("Acquired GenerateKyberKeyPairInternal mutex after {Backoff}ms", backoff);

        try
        {
            MLKemKeyGenerationParameters kyber_generation_parameters = new(SecureRandom, MLKemParameters.ml_kem_1024);
            MLKemKeyPairGenerator keypair_generator = new();
            keypair_generator.Init(kyber_generation_parameters);
            key_pair = keypair_generator.GenerateKeyPair();
        }
        finally
        {
            mutex.ReleaseMutex(); // AbsorbBits in GenerateKeyPair() cannot handle threading.
        }

        return key_pair;
    }

    internal static byte[] GetChrystalsKyberPublicKeyFromEncoded(AsymmetricCipherKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        var publicKey = (MLKemPublicKeyParameters)keyPair.Public;
        var publicKeyBytes = publicKey.GetEncoded();
        return publicKeyBytes;
    }

    internal static byte[] GetChrystalsKyberPrivateKeyFromEncoded(AsymmetricCipherKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        var privateKey = (MLKemPrivateKeyParameters)keyPair.Private;
        var privateKeyBytes = privateKey.GetEncoded();
        return privateKeyBytes;
    }

    internal static (ImmutableArray<byte> encapsulatedKey, ImmutableArray<byte> sessionSharedKey) ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey(ReadOnlySpan<byte> publicKeyBytes, ILogger? logger)
    {
        var publicKey = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, [.. publicKeyBytes]);

        MLKemEncapsulator enc = new(MLKemParameters.ml_kem_1024);
        enc.Init(publicKey);

        var cipherTextBytes = new byte[enc.EncapsulationLength];
        var cipherTextSpan = cipherTextBytes.AsSpan();

        var sharedSecretBytes = new byte[enc.SecretLength];
        var sharedSecretSpan = sharedSecretBytes.AsSpan();

        // Exponential backoff
        const int baseBackoff = 100;
        var failcount = 0;
        var backoff = baseBackoff;
        bool okay;
        do
        {
            okay = mutex.WaitOne(backoff);
            if (!okay)
            {
                failcount++;
                backoff = (int)Math.Pow(baseBackoff, failcount + 1);
            }
        } while (!okay);
        logger?.LogTrace("Acquired GenerateChrystalsKyberEncryptionKey mutex after {Backoff}ms", backoff);

        try
        {
            // Encapsulate
            enc.Encapsulate(cipherTextSpan, sharedSecretSpan);
        }
        finally
        {
            mutex.ReleaseMutex(); // AbsorbBits in GenerateKeyPair() cannot handle threading.
        }

        return (cipherTextBytes.ToImmutableArray(), sharedSecretBytes.ToImmutableArray());
    }

    internal static ImmutableArray<byte> GenerateChrystalsKyberDecryptionKey(ImmutableArray<byte> privateKeyBytes, ReadOnlySpan<byte> encapsulatedKey, ILogger? logger)
    {
        var privateKey = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, [.. privateKeyBytes]);
        return GenerateChrystalsKyberDecryptionKey(privateKey, encapsulatedKey, logger);
    }

    internal static ImmutableArray<byte> GenerateChrystalsKyberDecryptionKey(MLKemPrivateKeyParameters privateKey, ReadOnlySpan<byte> encapsulatedKey, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        MLKemDecapsulator dec = new(MLKemParameters.ml_kem_1024);
        dec.Init(privateKey);

        if (encapsulatedKey.Length != dec.EncapsulationLength)
        {
            throw new ArgumentException("", nameof(encapsulatedKey));
        }

        var sharedSecretBytes = new byte[dec.SecretLength];
        var sharedSecretSpan = sharedSecretBytes.AsSpan();

        // Exponential backoff
        const int baseBackoff = 100;
        var failcount = 0;
        var backoff = baseBackoff;
        bool okay;
        do
        {
            okay = mutex.WaitOne(backoff);
            if (!okay)
            {
                failcount++;
                backoff = (int)Math.Pow(baseBackoff, failcount + 1);
            }
        } while (!okay);
        logger?.LogTrace("Acquired GenerateChrystalsKyberDecryptionKey mutex after {Backoff}ms", backoff);

        try
        {
            // Decapsulate
            dec.Decapsulate(encapsulatedKey, sharedSecretSpan);
        }
        finally
        {
            mutex.ReleaseMutex(); // AbsorbBits in GenerateKeyPair() cannot handle threading.
        }

        return [.. sharedSecretBytes];
    }

    internal static Messages.Envelope EncryptEnvelopeInternal(byte[] envelopePayload, ImmutableArray<byte>? sharedKey, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(envelopePayload);

        Messages.Envelope envelope;
        byte[] nonce = new byte[12];
        byte[] plain_text = envelopePayload;
        byte[] cipher_text = new byte[plain_text.Length];
        byte[] tag = new byte[16];
        byte[]? associated_data = null;

        if (sharedKey == null)
        {
            // Loopback
            envelope = new Messages.Envelope
            {
                Nonce = ByteString.CopyFrom(nonce),
                Ciphertext = ByteString.CopyFrom(plain_text), // No encryption for loopback
                Tag = ByteString.CopyFrom(tag),
                AssociatedData = associated_data == null ? ByteString.Empty : ByteString.CopyFrom(associated_data)
            };
        }
        else
        {
            try
            {
                using ChaCha20Poly1305 cha = new(sharedKey.Value.AsSpan());
                RandomNumberGenerator.Fill(nonce);
                RandomNumberGenerator.Fill(associated_data);
                cha.Encrypt(nonce, plain_text, cipher_text, tag, associated_data);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to encrypt payload");
                throw;
            }

            envelope = new Messages.Envelope
            {
                Nonce = ByteString.CopyFrom(nonce),
                Ciphertext = ByteString.CopyFrom(cipher_text),
                Tag = ByteString.CopyFrom(tag),
                AssociatedData = associated_data == null ? ByteString.Empty : ByteString.CopyFrom(associated_data)
            };
        }

        //MessageUtils.Dump(envelope, logger);
        //Console.WriteLine($"SESSION KEY HASH={CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey))}");
        return envelope;
    }

    internal static ReadOnlySpan<byte> DecryptEnvelopeInternal(Messages.Envelope envelope, ReadOnlySpan<byte> sharedKey, ILogger? logger) => DecryptEnvelopeInternal(new Apps.Common.Envelope
    {
        Nonce = envelope.Nonce.Span,
        Ciphertext = envelope.Ciphertext.Span,
        Tag = envelope.Tag.Span,
        AssociatedData = envelope.AssociatedData.Span,
    }, sharedKey, logger);

    internal static ReadOnlySpan<byte> DecryptEnvelopeInternal(Apps.Common.Envelope envelope, ReadOnlySpan<byte> sharedKey, ILogger? logger)
    {
        if (sharedKey.IsEmpty)
        {
            // Loopback
            return envelope.Ciphertext;
        }

        //MessageUtils.Dump(envelope, logger);
        byte[] envelope_plain_text = new byte[envelope.Ciphertext.Length];

        try
        {
            using ChaCha20Poly1305 cha = new(sharedKey);
            cha.Decrypt(
                envelope.Nonce
                , envelope.Ciphertext
                , envelope.Tag
                , envelope_plain_text
                , envelope.AssociatedData);
        }
        catch (AuthenticationTagMismatchException atme)
        {
            logger?.LogError(atme, "Failed to decrypt message. Incorrect session key?");
            throw;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to decrypt message; closing down connection to victim");
            throw;
        }

        return envelope_plain_text;
    }

    internal static bool ValidateDilithiumSignature(ImmutableArray<byte> publicKey, byte[] message, byte[] signature)
    {
        var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_87, true);
        var parms = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, [.. publicKey]);
        verifier.Init(false, parms);
        verifier.BlockUpdate(message);
        return verifier.VerifySignature(signature);
    }

    private const string DEFAULT_CHARACTER_SET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    internal static string ConvertToBase62(this byte[] arr)
    {
        var converted = BaseConvert(arr, 256, 62);
        var builder = new StringBuilder();
        foreach (var c in converted)
        {
            builder.Append(DEFAULT_CHARACTER_SET[c]);
        }
        return builder.ToString();
    }

    internal static byte[] ConvertFromBase62(this string base62)
    {
        var arr = new byte[base62.Length];
        for (var i = 0; i < arr.Length; i++)
        {
            arr[i] = (byte)DEFAULT_CHARACTER_SET.IndexOf(base62[i]);
        }

        return BaseConvert(arr, 62, 256);
    }

    /// <summary>
    /// Converts source byte array from the source base to the destination base.
    /// </summary>
    /// <param name="source">Byte array to convert.</param>
    /// <param name="sourceBase">Source base to convert from.</param>
    /// <param name="targetBase">Target base to convert to.</param>
    /// <returns>Converted byte array.</returns>
    private static byte[] BaseConvert(byte[] source, int sourceBase, int targetBase)
    {
        if (targetBase < 2 || targetBase > 256)
            throw new ArgumentOutOfRangeException(nameof(targetBase), targetBase, "Value must be between 2 & 256 (inclusive)");

        if (sourceBase < 2 || sourceBase > 256)
            throw new ArgumentOutOfRangeException(nameof(sourceBase), sourceBase, "Value must be between 2 & 256 (inclusive)");

        // Set initial capacity estimate if the size is small.
        var startCapacity = source.Length < 1028
            ? (int)(source.Length * 1.5)
            : source.Length;

        var result = new List<int>(startCapacity);
        var quotient = new List<byte>((int)(source.Length * 0.5));
        int count;
        int initialStartOffset = 0;

        // This is a bug fix for the following issue:
        // https://github.com/ghost1face/base62/issues/4
        while (source[initialStartOffset] == 0)
        {
            result.Add(0);
            initialStartOffset++;
        }

        int startOffset = initialStartOffset;

        while ((count = source.Length) > 0)
        {
            quotient.Clear();
            int remainder = 0;
            for (var i = initialStartOffset; i != count; i++)
            {
                int accumulator = source[i] + remainder * sourceBase;
                byte digit = (byte)((accumulator - (accumulator % targetBase)) / targetBase);
                remainder = accumulator % targetBase;
                if (quotient.Count > 0 || digit != 0)
                {
                    quotient.Add(digit);
                }
            }

            result.Insert(startOffset, remainder);
            source = quotient.ToArray();
            initialStartOffset = 0;
        }

        var output = new byte[result.Count];

        for (int i = 0; i < result.Count; i++)
            output[i] = (byte)result[i];

        return output;
    }

}