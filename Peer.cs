using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;

namespace Luxelot;

internal class Peer : IDisposable
{
    private bool disposed = false;

    public string PeerName { get; private set; } = "<Unset>";
    public string PeerShortName { get; private set; } = "<Unset>";
    public ImmutableArray<byte>? IdentityPublicKey { get; private set; }
    public ImmutableArray<byte>? IdentityPublicKeyThumbprint { get; private set; }
    public ImmutableArray<byte>? SessionPublicKey { get; init; }
    private ImmutableArray<byte>? SessionPrivateKey { get; init; }
    public ImmutableArray<byte>? SessionSharedKey { get; private set; }
    public DateTimeOffset LastActivity { get; set; } = DateTimeOffset.Now;
    private TcpClient Client { get; init; }
    public ulong BytesReceived { get; private set; } = 0;

    public EndPoint? LocalEndPoint => disposed ? throw new ObjectDisposedException(nameof(Client)) : Client.Client?.LocalEndPoint;
    public EndPoint? RemoteEndPoint => disposed ? throw new ObjectDisposedException(nameof(Client)) : Client.Client?.RemoteEndPoint;
    public bool IsReadable => !disposed && Client.Connected && Client.GetStream().CanRead;
    public bool IsWriteable => !disposed && Client.Connected && Client.GetStream().CanWrite;

    private Peer(TcpClient tcpClient)
    {
        Client = tcpClient;
    }

    internal static Peer CreatePeerFromAccept(TcpClient tcpClient, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        var peer = new Peer(tcpClient)
        {
            SessionPublicKey = null,
            SessionPrivateKey = null,
            SessionSharedKey = null, // Computed after Syn received
        };
        return peer;
    }

    internal static Peer CreatePeerToConnect(TcpClient tcpClient, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        var (publicKeyBytes, privateKeyBytes) = GenerateKeysForPeer(logger);
        var peer = new Peer(tcpClient)
        {
            SessionPublicKey = publicKeyBytes,
            SessionPrivateKey = privateKeyBytes,
            SessionSharedKey = null // Computed after Ack received
        };
        return peer;
    }

    private byte[] ComputeSessionSharedKeyFromSynAndGetCipherText(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (SessionSharedKey != null)
            throw new InvalidOperationException("Shared key already computed!");

        KyberPublicKeyParameters peer_public = new(KyberParameters.kyber1024, publicKey);
        var secretKeyWithEncapsulationSender = CryptoUtils.GenerateChrystalsKyberEncryptionKey(peer_public);

        // Shared Key
        var encryptionKey = secretKeyWithEncapsulationSender.GetSecret();
        SessionSharedKey = encryptionKey.ToImmutableArray();

        var encapsulatedKey = secretKeyWithEncapsulationSender.GetEncapsulation();
        return encapsulatedKey;
    }

    private void ComputeSessionSharedKeyFromAckCipherText(ImmutableArray<byte> encapsulatedKey)
    {
        ArgumentNullException.ThrowIfNull(encapsulatedKey);

        if (SessionSharedKey != null)
            throw new InvalidOperationException("Shared key already computed!");
        if (SessionPrivateKey == null)
            throw new InvalidOperationException("Private key not set!");

        // Shared Key
        var decryptionKey = CryptoUtils.GenerateChrystalsKyberDecryptionKey(SessionPrivateKey.Value, encapsulatedKey);
        SessionSharedKey = decryptionKey;
    }

    private static (ImmutableArray<byte> publicKeyBytes, ImmutableArray<byte> privateKeyBytes) GenerateKeysForPeer(ILogger logger)
    {
        //byte[] encryptionKey, encapsulatedKey, decryptionKey;
        byte[] publicKeyBytes, privateKeyBytes;

        using (logger.BeginScope($"Crypto setup"))
        {
            // Generate Kyber crypto material for our comms with this peer.
            logger.LogInformation("Generating cryptographic key material");
            AsymmetricCipherKeyPair node_key;
            try
            {
                node_key = CryptoUtils.GenerateKyberKeyPair();
                logger.LogDebug("Geneated Kyber key pair!");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unable to generate Kyber key pair");
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

            logger.LogTrace("Generated private key length: {PrivateKeyByteLength}", privateKeyBytes.Length);
            publicKeyBytes = CryptoUtils.GetChrystalsKyberPublicKeyFromEncoded(node_key);
            logger.LogTrace("Generated public key length: {PublicKeyByteLength}", publicKeyBytes.Length);

            logger.LogDebug("Key pairs successfully generated");
        }

        return (publicKeyBytes.ToImmutableArray(), privateKeyBytes.ToImmutableArray());
    }

    internal NetworkStream GetStream() => Client.GetStream();

    internal async Task<bool> HandleSyn(NodeContext nodeContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);

        // We expect a Syn (with a public key).  Calculate the Kyber cipher text and send back an Ack.
        var stream = Client.GetStream();
        if (!stream.CanRead || !stream.CanWrite)
            return false;

        int size = 4168; // Special case since we know exactly field sizes for Syn.
        var buffer = new byte[size];
        try
        {
            await stream.ReadExactlyAsync(buffer, 0, size, cancellationToken: cancellationToken);
            BytesReceived += (ulong)size;
        }
        catch (EndOfStreamException ex)
        {
            nodeContext.Logger?.LogWarning(ex, "End of stream from peer {RemoteEndPoint} before Syn could be processed. Closing.", RemoteEndPoint);
            Client.Close();
            return false;
        }

        Syn syn;
        try
        {
            syn = Syn.Parser.ParseFrom(buffer, 0, size);
        }
        catch (InvalidProtocolBufferException ex)
        {
            nodeContext.Logger?.LogError(ex, "Invalid Syn from {RemoteEndPoint} could not be parsed. Closing.", RemoteEndPoint);
            Client.Close();
            return false;
        }

        using var scope = nodeContext.Logger?.BeginScope("Process Syn from {RemoteEndPoint}", RemoteEndPoint);
        var encapsulatedKey = ComputeSessionSharedKeyFromSynAndGetCipherText(syn.SessionPubKey.ToByteArray());

        // This peer's identity key was received in Syn.
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer at {RemoteEndPoint} should have an empty identity public key field at Syn time!");

        var id_pub_key_bytes = syn.IdPubKey.ToByteArray();
        IdentityPublicKey = id_pub_key_bytes.ToImmutableArray();
        IdentityPublicKeyThumbprint = SHA256.HashData(id_pub_key_bytes).ToImmutableArray();
        PeerName = CryptoUtils.BytesToHex(IdentityPublicKeyThumbprint);
        PeerShortName = $"{PeerName[..8]}...";

        nodeContext.Logger?.LogDebug("ID Key for {PeerShortName} ({RemoteEndPoint}) is thumbprint {Thumbprint}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(IdentityPublicKeyThumbprint));
        //nodeContext.Logger?.LogCritical("SESSION KEY HASH {PeerShortName} ({peer.RemoteEndPoint})={SessionKeyHash}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey!)));
        nodeContext.Logger?.LogDebug("Sending Ack to peer {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);
        var message = new Ack
        {
            ProtVer = Node.PROTOCOL_VERSION,
            CipherText = ByteString.CopyFrom(encapsulatedKey),
            // Now provide our own identity key in the response Ack
            IdPubKey = ByteString.CopyFrom([.. nodeContext.NodeIdentityKeyPublicBytes]),
        };

        await stream.WriteAsync(message.ToByteArray(), cancellationToken);
        return true;
    }

    internal async Task<bool> HandleAck(NodeContext nodeContext, CancellationToken cancellationToken)
    {
        // Here we will get what we need to compute the shared secret.
        // At the start of this, we should NOT have any identity key, as that comes in the Ack.
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer {PeerShortName} already has an identity public key by the time this Ack was recieved.");

        // We expect a Ack (with a cipher text).  Calculate the shared key and send back an encrypted SynAck.
        var stream = Client.GetStream();
        if (!stream.CanRead || !stream.CanWrite)
            return false;

        int size = 4168; // Special case since we know exactly field sizes for Ack.
        var buffer = new byte[size];
        try
        {
            await stream.ReadExactlyAsync(buffer, 0, size, cancellationToken: cancellationToken);
            BytesReceived += (ulong)size;
        }
        catch (EndOfStreamException ex)
        {
            nodeContext.Logger?.LogWarning(ex, "End of stream from peer {RemoteEndPoint} before Ack could be processed. Closing.", RemoteEndPoint);
            Client.Close();
            return false;
        }

        Ack ack;
        try
        {
            ack = Ack.Parser.ParseFrom(buffer, 0, size);
            if (ack.CipherText == null || ack.CipherText.Length != 1568)
            {
                nodeContext.Logger?.LogError("Invalid Ack (CipherText) from {RemoteEndPoint} could not be parsed. Closing.", RemoteEndPoint);
                Client.Close();
                return false;
            }
            if (ack.IdPubKey == null || ack.IdPubKey.Length != 2592)
            {
                nodeContext.Logger?.LogError("Invalid Ack (IdPubKey) from {RemoteEndPoint} could not be parsed. Closing.", RemoteEndPoint);
                Client.Close();
                return false;
            }

        }
        catch (InvalidProtocolBufferException ex)
        {
            nodeContext.Logger?.LogError(ex, "Invalid Ack from {RemoteEndPoint} could not be parsed. Closing.", RemoteEndPoint);
            Client.Close();
            return false;
        }

        using var scope = nodeContext.Logger?.BeginScope("Process Ack from {RemoteEndPoint}", RemoteEndPoint);

        ComputeSessionSharedKeyFromAckCipherText([.. ack.CipherText.ToByteArray()]);
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer {PeerName} should have an empty identity public key field at Ack time!");

        var id_pub_key_bytes = ack.IdPubKey.ToByteArray();
        IdentityPublicKey = id_pub_key_bytes.ToImmutableArray();
        IdentityPublicKeyThumbprint = SHA256.HashData(id_pub_key_bytes).ToImmutableArray();
        PeerName = CryptoUtils.BytesToHex(IdentityPublicKeyThumbprint);
        PeerShortName = $"{PeerName[..8]}...";

        //nodeContext.Logger?.LogCritical("SESSION KEY HASH {PeerShortName} ({peer.RemoteEndPoint})={SessionKeyHash}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey!)));
        return true;
    }

    internal async Task<bool> HandleInputAsync(
        ConcurrentDictionary<string, ImmutableArray<byte>> thumbnailSignatureCache,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thumbnailSignatureCache);
        ObjectDisposedException.ThrowIf(disposed, Client);

        if (SessionSharedKey == null || Client.Available == 0)
        {
            return true; // We don't need to shut it down, we just don't need to do anything here.
        }

        // Fully established with data to read.
        var buffer = new byte[16 * 1024]; // 16 kb
        int size;
        try
        {
            size = await Client.GetStream().ReadAsync(buffer, cancellationToken: cancellationToken);
            BytesReceived += (ulong)size;
        }
        catch (EndOfStreamException ex)
        {
            logger.LogWarning(ex, "End of stream from peer {PeerShortName} ({RemoteEndPoint}) could be processed. Closing.", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }

        Envelope envelope;
        try
        {
            envelope = Envelope.Parser.ParseFrom(buffer, 0, size);
        }
        catch (InvalidProtocolBufferException ex)
        {
            logger.LogError(ex, "Invalid Envelope from {PeerShortName} ({RemoteEndPoint}) could not be parsed. Closing.", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }

        // Decrypt envelope contents.
        //MessageUtils.Dump(envelope, logger);
        //Console.WriteLine($"SESSION KEY HASH={CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey))}");

        byte[] nonce = envelope.Nonce.ToByteArray();
        byte[] cipher_text = envelope.Ciphertext.ToByteArray();
        byte[] envelope_plain_text = new byte[cipher_text.Length];
        byte[] tag = envelope.Tag.ToByteArray();
        byte[] associated_data = envelope.AssociatedData.ToByteArray();
        try
        {
            using ChaCha20Poly1305 cha = new([.. SessionSharedKey.Value]);
            cha.Decrypt(nonce, cipher_text, tag, envelope_plain_text, associated_data);
        }
        catch (AuthenticationTagMismatchException atme)
        {
            logger.LogError(atme, "Failed to decrypt message; closing down connection to victim {PeerShortName} ({RemoteEndPoint}). Incorrect session key?", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to decrypt message; closing down connection to victim {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }
        logger.LogTrace("Decrypted message from {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);

        EnvelopePayload envelopePayload;
        try
        {
            envelopePayload = EnvelopePayload.Parser.ParseFrom(envelope_plain_text, 0, envelope_plain_text.Length);
        }
        catch (InvalidProtocolBufferException ex)
        {
            logger.LogError(ex, "Invalid EnvelopePayload from {PeerShortName} ({RemoteEndPoint}) could not be parsed. Closing.", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }

        if (envelopePayload.DirectedMessage != null)
        {
            var dm = envelopePayload.DirectedMessage;
            // Is this destined for me?
            if (Enumerable.SequenceEqual(IdentityPublicKeyThumbprint, dm.DstIdentityPublicKeyThumbprint))
            {
                logger.LogTrace("Discarding message intended for node thumbprint {Thumbprint1}.  I have thumbprint {Thumbprint2}.", CryptoUtils.BytesToHex(dm.DstIdentityPublicKeyThumbprint), CryptoUtils.BytesToHex(IdentityPublicKeyThumbprint));
                // TODO: Implement routing to other node, if possible.
                return true;
            }

            // Is the signature valid?
            if (!thumbnailSignatureCache.TryGetValue(CryptoUtils.BytesToHex(dm.SrcIdentityPublicKeyThumbprint), out ImmutableArray<byte> sourceIdentityPublicKey))
            {
                logger.LogError("Discarding message with unverifiable signature for unknown thumbprint {Thumbprint}.", CryptoUtils.BytesToHex(dm.SrcIdentityPublicKeyThumbprint));
                return false;
            }
            var sourceVerify = new DilithiumSigner();
            DilithiumPublicKeyParameters parms = new(DilithiumParameters.Dilithium5, [.. sourceIdentityPublicKey]);
            sourceVerify.Init(false, parms);
            var dm_payload = dm.Payload.ToByteArray();
            if (!sourceVerify.VerifySignature(dm_payload, dm.Signature.ToByteArray()))
            {
                logger.LogError("Discarding message with invalid signature for known thumbprint {Thumbprint}.", CryptoUtils.BytesToHex(dm.SrcIdentityPublicKeyThumbprint));
                return false;
            }

            switch (dm.Payload)
            {
                case Any any when any.Is(ConsoleAlert.Descriptor):
                    logger.LogCritical("CONSOLE ALERT from {PeerShortName} ({RemoteEndPoint}): {Contents}", PeerShortName, RemoteEndPoint, any.Unpack<ConsoleAlert>().Message);
                    break;
                case Any any when any.Is(Ping.Descriptor):
                    var ping = any.Unpack<Ping>();
                    logger.LogCritical("PING {PeerShortName} ({RemoteEndPoint}): {Contents}", PeerShortName, RemoteEndPoint, $"id={ping.Identifier},seq={ping.Sequence}");
                    break;
                default:
                    logger.LogCritical("From {PeerShortName} ({RemoteEndPoint}): {Contents}", PeerShortName, RemoteEndPoint, Encoding.UTF8.GetString(dm.Payload.ToByteArray()));
                    break;
            }
            return true;
        }

        logger.LogError("Unsupported envelope payload received from {PeerShortName} ({RemoteEndPoint}. Closing.", PeerShortName, RemoteEndPoint);
        return false;
    }

    public void Close() => Client.Close();

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposed) return;

        if (disposing)
        {
            Client?.Dispose();
        }

        disposed = true;
    }

    public Envelope PrepareEnvelope(NodeContext nodeContext, DirectedMessage directedMessage)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(directedMessage);

        var envelope_payload = new EnvelopePayload
        {
            DirectedMessage = directedMessage
        };

        var envelope_payload_bytes = envelope_payload.ToByteArray();
        return PrepareEnvelope(nodeContext, envelope_payload_bytes);
    }

    private Envelope PrepareEnvelope(NodeContext nodeContext, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(payload);
        if (SessionSharedKey == null || SessionSharedKey.Value.Length == 0)
        {
            nodeContext.Logger?.LogError("Session key is not established with peer {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);
            throw new InvalidOperationException($"Session key is not established with peer {PeerShortName} ({RemoteEndPoint})");
        }

        byte[] nonce = new byte[12];
        byte[] plain_text = payload;
        byte[] cipher_text = new byte[plain_text.Length];
        byte[] tag = new byte[16];
        byte[]? associated_data = null; //new byte[4];
        try
        {
            using ChaCha20Poly1305 cha = new([.. SessionSharedKey.Value]);
            RandomNumberGenerator.Fill(nonce);
            RandomNumberGenerator.Fill(associated_data);
            cha.Encrypt(nonce, plain_text, cipher_text, tag, associated_data);
        }
        catch (Exception ex)
        {
            nodeContext.Logger?.LogError(ex, "Failed to encrypt payload; closing down connection to victim {PeerShortName} ({RemoteEndPoint}).", PeerShortName, RemoteEndPoint);
            throw;
        }

        var envelope = new Envelope
        {
            Nonce = ByteString.CopyFrom(nonce),
            Ciphertext = ByteString.CopyFrom(cipher_text),
            Tag = ByteString.CopyFrom(tag),
            AssociatedData = associated_data == null ? ByteString.Empty : ByteString.CopyFrom(associated_data)
        };
        //MessageUtils.Dump(envelope, nodeContext.Logger);
        //Console.WriteLine($"SESSION KEY HASH={CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey))}");
        return envelope;
    }

    public async Task SendSyn(NodeContext nodeContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);

        if (SessionPublicKey == null) {
            throw new InvalidOperationException("SessionPublicKey not set, but I am the one sending the syn!");
        }

        var message = new Syn
        {
            ProtVer = Node.PROTOCOL_VERSION,
            SessionPubKey = ByteString.CopyFrom([.. SessionPublicKey.Value]),
            IdPubKey = ByteString.CopyFrom([.. nodeContext.NodeIdentityKeyPublicBytes])
        };
        await GetStream().WriteAsync(message.ToByteArray(), cancellationToken);
    }

    public async Task SendEnvelope(Envelope envelope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        await Client.GetStream().WriteAsync(envelope.ToByteArray(), cancellationToken);
    }
}

