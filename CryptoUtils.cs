using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace Luxelot;

public static class CryptoUtils
{
    private static Mutex mutex = new();
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
        var publicKey = (KyberPublicKeyParameters)keyPair.Public;
        var publicKeyBytes = publicKey.GetEncoded();
        return publicKeyBytes;
    }

    public static byte[] GetChrystalsKyberPrivateKeyFromEncoded(AsymmetricCipherKeyPair keyPair)
    {
        var privateKey = (KyberPrivateKeyParameters)keyPair.Private;
        var privateKeyBytes = privateKey.GetEncoded();
        return privateKeyBytes;
    }

    public static ISecretWithEncapsulation GenerateChrystalsKyberEncryptionKey(KyberPublicKeyParameters publicKey)
    {
        KyberKemGenerator kem_generator = new(SecureRandom);
        var secret_with_encapsulation = kem_generator.GenerateEncapsulated(publicKey);
        return secret_with_encapsulation;
    }

    public static byte[] GenerateChrystalsKyberDecryptionKey(byte[] privateKeyBytes, byte[] encapsulatedKey)
    {
        var privateKey = new KyberPrivateKeyParameters(KyberParameters.kyber1024, privateKeyBytes);
        return GenerateChrystalsKyberDecryptionKey(privateKey, encapsulatedKey);
    }

    public static byte[] GenerateChrystalsKyberDecryptionKey(KyberPrivateKeyParameters privateKey, byte[] encapsulatedKey)
    {
        KyberKemExtractor extractor = new KyberKemExtractor(privateKey);
        var key_bytes = extractor.ExtractSecret(encapsulatedKey);
        return key_bytes;
    }

    public static string BytesToHex(IEnumerable<byte> bytes)
    {
        StringBuilder result = new();
        foreach (byte b in bytes)
            _ = result.Append(Convert.ToString((b & 0xff) + 0x100, 16)[1..]);
        return result.ToString();
    }
}