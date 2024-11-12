using System.Collections.Immutable;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

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

    public static AsymmetricCipherKeyPair GenerateKyberKeyPair()
    {
        // These keys are used for PEER ENCRYPTION.  A shared key is established using
        // the Kyber KEM process, and these are not ferried around the network.

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

    public static ISecretWithEncapsulation GenerateChrystalsKyberEncryptionKey(ImmutableArray<byte> publicKeyBytes)
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

    public static bool ValidateDilithiumSignature(ImmutableArray<byte> publicKey, byte[] message, byte[] signature)
    {
        var sourceVerify = new DilithiumSigner();
        DilithiumPublicKeyParameters parms = new(DilithiumParameters.Dilithium5, [.. publicKey]);
        sourceVerify.Init(false, parms);
        return sourceVerify.VerifySignature(message, signature);
    }

    public static string BytesToHex(IEnumerable<byte>? bytes) =>
        bytes == null ? string.Empty : Convert.ToHexString(bytes.ToArray());

    public static byte[] HexToBytes(string hex)
    {
        try {
            return string.IsNullOrWhiteSpace(hex) ? [] : Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            // Swallow.
            return [];
        }
    }
}