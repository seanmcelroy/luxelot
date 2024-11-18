using System.Collections.Immutable;
using System.Security.Cryptography;
using Google.Protobuf;
using Luxelot.App.Common.Messages;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace Luxelot;

public static class CryptoUtils
{
    private static readonly Mutex mutex = new();
    private readonly static SecureRandom SecureRandom = new();

    // Kyber - Super helpful: https://stackoverflow.com/questions/75240825/implementing-crystals-kyber-using-bouncycastle-java
    // Dilithium - Super helpful: https://asecuritysite.com/bouncy/bc_dil

    public static AsymmetricCipherKeyPair GenerateDilithiumKeyPair()
    {
        // These keys are used for NODE IDENTITY.  The node can sign envelopes forwarded
        // by other nodes around the network.

        DilithiumKeyGenerationParameters keyGenParameters = new(SecureRandom, DilithiumParameters.Dilithium5);
        DilithiumKeyPairGenerator keyPairGen = new();
        keyPairGen.Init(keyGenParameters);
        var keyPair = keyPairGen.GenerateKeyPair();
        return keyPair;
    }

    internal static (ImmutableArray<byte> publicKeyBytes, ImmutableArray<byte> privateKeyBytes) GenerateKyberKeyPair(ILogger? logger)
    {
        byte[] publicKeyBytes, privateKeyBytes;

        using (logger?.BeginScope($"Crypto setup"))
        {
            // Generate Kyber crypto material for our comms with this peer.
            logger?.LogInformation("Generating cryptographic key material");
            AsymmetricCipherKeyPair node_key;
            try
            {
                node_key = GenerateKyberKeyPairInternal();
                logger?.LogDebug("Geneated Kyber key pair!");
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

            privateKeyBytes = CryptoUtils.GetChrystalsKyberPrivateKeyFromEncoded(node_key);
            //decryptionKey = CryptoUtils.GenerateChrystalsKyberDecryptionKey(privateKeyBytes, encapsulatedKey);
            //var keysAreEqual = Enumerable.SequenceEqual(encryptionKey, decryptionKey);

            //logger.LogInformation("Decryption side: receive the encapsulated key and generate the decryption key\r\n"
            //    + $"Decryption key length: {decryptionKey.Length} key: {CryptoUtils.BytesToHex(decryptionKey)}"
            //    + $"Decryption key is equal to encryption key: {keysAreEqual}");

            logger?.LogTrace("Generated private key length: {PrivateKeyByteLength}", privateKeyBytes.Length);
            publicKeyBytes = CryptoUtils.GetChrystalsKyberPublicKeyFromEncoded(node_key);
            logger?.LogTrace("Generated public key length: {PublicKeyByteLength}", publicKeyBytes.Length);

            logger?.LogDebug("Key pairs successfully generated");
        }

        return (publicKeyBytes.ToImmutableArray(), privateKeyBytes.ToImmutableArray());
    }

    private static AsymmetricCipherKeyPair GenerateKyberKeyPairInternal()
    {
        // These keys are used for PEER (neighor across the network) CHANNEL ENCRYPTION.
        // A shared key is established using the Kyber KEM process,
        // and these are not ferried around the network.

        AsymmetricCipherKeyPair key_pair;

        var okay = mutex.WaitOne(10000);
        if (!okay)
        {
            throw new InvalidOperationException();
        }
        try
        {
            KyberKeyGenerationParameters kyber_generation_parameters = new(SecureRandom, KyberParameters.kyber1024);
            KyberKeyPairGenerator keypair_generator = new();
            keypair_generator.Init(kyber_generation_parameters);
            key_pair = keypair_generator.GenerateKeyPair();
        }
        finally
        {
            mutex.ReleaseMutex(); // AbsorbBits in GenerateKeyPair() cannot handle threading.
        }

        return key_pair;
    }

    public static byte[] GetChrystalsKyberPublicKeyFromEncoded(AsymmetricCipherKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        var publicKey = (KyberPublicKeyParameters)keyPair.Public;
        var publicKeyBytes = publicKey.GetEncoded();
        return publicKeyBytes;
    }

    public static byte[] GetChrystalsKyberPrivateKeyFromEncoded(AsymmetricCipherKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        var privateKey = (KyberPrivateKeyParameters)keyPair.Private;
        var privateKeyBytes = privateKey.GetEncoded();
        return privateKeyBytes;
    }

    public static (byte[] encapsulatedKey, ImmutableArray<byte> sessionSharedKey) ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey(ImmutableArray<byte> publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var secretKeyWithEncapsulationSender = GenerateChrystalsKyberEncryptionKey(publicKey);

        // Shared Key
        var encryptionKey = secretKeyWithEncapsulationSender.GetSecret();
        var sessionSharedKey = encryptionKey.ToImmutableArray();

        // Encapsulated key (cipher text)
        var encapsulatedKey = secretKeyWithEncapsulationSender.GetEncapsulation();
        return (encapsulatedKey, sessionSharedKey);
    }

    private static ISecretWithEncapsulation GenerateChrystalsKyberEncryptionKey(ImmutableArray<byte> publicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(publicKeyBytes);

        KyberPublicKeyParameters publicKey = new(KyberParameters.kyber1024, [.. publicKeyBytes]);
        ISecretWithEncapsulation secret_with_encapsulation;

        var okay = mutex.WaitOne(10000);
        if (!okay)
        {
            throw new InvalidOperationException();
        }
        try
        {
            KyberKemGenerator kem_generator = new(SecureRandom);
            secret_with_encapsulation = kem_generator.GenerateEncapsulated(publicKey);
        }
        finally
        {
            mutex.ReleaseMutex(); // AbsorbBits in GenerateKeyPair() cannot handle threading.
        }

        return secret_with_encapsulation;
    }

    public static ImmutableArray<byte> GenerateChrystalsKyberDecryptionKey(ImmutableArray<byte> privateKeyBytes, ImmutableArray<byte> encapsulatedKey)
    {
        ArgumentNullException.ThrowIfNull(privateKeyBytes);
        ArgumentNullException.ThrowIfNull(encapsulatedKey);

        var privateKey = new KyberPrivateKeyParameters(KyberParameters.kyber1024, [.. privateKeyBytes]);
        return GenerateChrystalsKyberDecryptionKey(privateKey, encapsulatedKey);
    }

    public static ImmutableArray<byte> GenerateChrystalsKyberDecryptionKey(KyberPrivateKeyParameters privateKey, ImmutableArray<byte> encapsulatedKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(encapsulatedKey);

        byte[] key_bytes;

        var okay = mutex.WaitOne(10000);
        if (!okay)
        {
            throw new InvalidOperationException();
        }
        try
        {
            KyberKemExtractor extractor = new(privateKey);
            key_bytes = extractor.ExtractSecret([.. encapsulatedKey]);
        }
        finally
        {
            mutex.ReleaseMutex(); // AbsorbBits in GenerateKeyPair() cannot handle threading.
        }

        return [.. key_bytes];
    }

    public static Envelope EncryptEnvelopeInternal(byte[] envelopePayload, ImmutableArray<byte> sharedKey, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(envelopePayload);
        ArgumentNullException.ThrowIfNull(sharedKey);

        byte[] nonce = new byte[12];
        byte[] plain_text = envelopePayload;
        byte[] cipher_text = new byte[plain_text.Length];
        byte[] tag = new byte[16];
        byte[]? associated_data = null;
        try
        {
            using ChaCha20Poly1305 cha = new([.. sharedKey]);
            RandomNumberGenerator.Fill(nonce);
            RandomNumberGenerator.Fill(associated_data);
            cha.Encrypt(nonce, plain_text, cipher_text, tag, associated_data);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to encrypt payload");
            throw;
        }

        var envelope = new Envelope
        {
            Nonce = ByteString.CopyFrom(nonce),
            Ciphertext = ByteString.CopyFrom(cipher_text),
            Tag = ByteString.CopyFrom(tag),
            AssociatedData = associated_data == null ? ByteString.Empty : ByteString.CopyFrom(associated_data)
        };

        //MessageUtils.Dump(envelope, logger);
        //Console.WriteLine($"SESSION KEY HASH={CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey))}");
        return envelope;
    }

    public static byte[] DecryptEnvelopeInternal(Envelope envelope, ImmutableArray<byte> sharedKey, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(sharedKey);

        //MessageUtils.Dump(envelope, logger);

        byte[] nonce = envelope.Nonce.ToByteArray();
        byte[] cipher_text = envelope.Ciphertext.ToByteArray();
        byte[] tag = envelope.Tag.ToByteArray();
        byte[] associated_data = envelope.AssociatedData.ToByteArray();

        byte[] envelope_plain_text = new byte[cipher_text.Length];

        try
        {
            using ChaCha20Poly1305 cha = new([.. sharedKey]);
            cha.Decrypt(nonce, cipher_text, tag, envelope_plain_text, associated_data);
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

    public static bool ValidateDilithiumSignature(ImmutableArray<byte> publicKey, byte[] message, byte[] signature)
    {
        var sourceVerify = new DilithiumSigner();
        DilithiumPublicKeyParameters parms = new(DilithiumParameters.Dilithium5, [.. publicKey]);
        sourceVerify.Init(false, parms);
        return sourceVerify.VerifySignature(message, signature);
    }
}