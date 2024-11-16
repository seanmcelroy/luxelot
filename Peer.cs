using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;

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
    public ulong BytesSent { get; private set; } = 0;

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

    private byte[] ComputeSessionSharedKeyFromSynAndGetCipherText(ImmutableArray<byte> publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (SessionSharedKey != null)
            throw new InvalidOperationException("Shared key already computed!");

        var secretKeyWithEncapsulationSender = CryptoUtils.GenerateChrystalsKyberEncryptionKey(publicKey);

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

    internal async Task<bool> HandleInputAsync(
        NodeContext nodeContext,
        ConcurrentDictionary<string, ImmutableArray<byte>> thumbnailSignatureCache,
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
            nodeContext.Logger?.LogWarning(ex, "End of stream from peer {PeerShortName} ({RemoteEndPoint}) could be processed. Closing.", PeerShortName, RemoteEndPoint);
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
            nodeContext.Logger?.LogError(ex, "Invalid Envelope from {PeerShortName} ({RemoteEndPoint}) could not be parsed. Closing.", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }

        // Decrypt envelope contents.
        //MessageUtils.Dump(envelope, nodeContext.Logger);
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
            nodeContext.Logger?.LogError(atme, "Failed to decrypt message; closing down connection to victim {PeerShortName} ({RemoteEndPoint}). Incorrect session key?", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }
        catch (Exception ex)
        {
            nodeContext.Logger?.LogError(ex, "Failed to decrypt message; closing down connection to victim {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }
        nodeContext.Logger?.LogTrace("Decrypted message from {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);

        EnvelopePayload envelopePayload;
        try
        {
            envelopePayload = EnvelopePayload.Parser.ParseFrom(envelope_plain_text, 0, envelope_plain_text.Length);
        }
        catch (InvalidProtocolBufferException ex)
        {
            nodeContext.Logger?.LogError(ex, "Invalid EnvelopePayload from {PeerShortName} ({RemoteEndPoint}) could not be parsed. Closing.", PeerShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }

        if (envelopePayload.ErrorMessage != null)
        {
            var em = envelopePayload.ErrorMessage;
            return HandleErrorMessage(nodeContext, em);
        }
        else if (envelopePayload.ForwardedMessage != null)
        {
            var fwd = envelopePayload.ForwardedMessage;
            nodeContext.Logger?.LogDebug("FORWARD FROM {PeerShortName} ({RemoteEndPoint}) intended for {DestinationThumbprint}: ForwardId={ForwardId}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(fwd.DstIdentityThumbprint), fwd.ForwardId);

            // Have I seen this message before?
            if (nodeContext.RegisterForwardId(fwd.ForwardId))
            {
                nodeContext.Logger?.LogTrace("Peer {PeerShortName} forwarded known message, ignoring: ForwardId={ForwardId}", PeerShortName, fwd.ForwardId);
                return true;
            }

            // Is the forwarded message purportedly from ME?  That's bogus, close client.
            if (fwd.SrcIdentityPubKey.SequenceEqual(nodeContext.NodeIdentityKeyPublicBytes))
            {
                nodeContext.Logger?.LogError("Peer {PeerShortName} forwarded message to me purportedly from myself: ForwardId={ForwardId}", PeerShortName, fwd.ForwardId);
                Client.Close();
                return false;
            }

            // Is the forwarded message destined for the sender?  That's a boomerang loop, close dumb client.
            if (IdentityPublicKeyThumbprint.HasValue
                && fwd.DstIdentityThumbprint.SequenceEqual(IdentityPublicKeyThumbprint.Value))
            {
                nodeContext.Logger?.LogError("Peer {PeerShortName} forwarded message to me destined for itself: ForwardId={ForwardId}", PeerShortName, fwd.ForwardId);
                Client.Close();
                return false;
            }

            // Is the forwarded message destined for a node OTHER THAN me?
            if (!fwd.DstIdentityThumbprint.SequenceEqual(nodeContext.NodeIdentityKeyPublicThumbprint))
            {
                if (fwd.Ttl <= 1)
                {
                    nodeContext.Logger?.LogCritical("Forwarded message TTL via {PeerShortName} has expired: ForwardId={ForwardId}", PeerShortName, fwd.ForwardId);
                    return true;
                }

                await nodeContext.RelayForwardMessage(fwd, IdentityPublicKeyThumbprint, cancellationToken);
                return true;
            }

            // This is a forwarded message for me.            
            nodeContext.Logger?.LogCritical("FORWARDED MESSAGE RECEIVED VIA {PeerShortName} ({RemoteEndPoint}): ForwardId={ForwardId}", PeerShortName, RemoteEndPoint, fwd.ForwardId);

            // Unwrap

            switch (fwd.Payload)
            {
                case Any any when any.Is(ErrorMessage.Descriptor):
                    var err = any.Unpack<ErrorMessage>();
                    return HandleErrorMessage(nodeContext, err);
                case Any any when any.Is(DirectedMessage.Descriptor):
                    var dm = any.Unpack<DirectedMessage>();
                    return await HandleDirectedMessage(nodeContext, dm, thumbnailSignatureCache, cancellationToken);
                case Any any when any.Is(ForwardedMessage.Descriptor):
                    nodeContext.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Forwarded message payload is another forwarded message.  Discarding.", PeerShortName, RemoteEndPoint);
                    Client.Close();
                    return true;
                default:
                    // This is the normal case, it's a forwarded message of some other type.

                    if (fwd.SrcIdentityPubKey == null)
                    {
                        nodeContext.Logger?.LogWarning("Discarding forward with missing src intended for {DestinationThumbprint}.", CryptoUtils.BytesToHex(fwd.DstIdentityThumbprint));
                        return true;
                    }

                    // Remember public key since we're observing it...
                    ImmutableArray<byte> fwd_src_pub_key = [.. fwd.SrcIdentityPubKey];

                    // NOTE: A little wasteful cycles to SHA256 on each fwd message just to check the cache.
                    byte[] fwd_origin_pub_thumbprint = [.. SHA256.HashData([.. fwd_src_pub_key])];

                    var cacheKey = CryptoUtils.BytesToHex(fwd_origin_pub_thumbprint);
                    if (!thumbnailSignatureCache.ContainsKey(cacheKey))
                    {
                        thumbnailSignatureCache.TryAdd(cacheKey, [.. fwd_src_pub_key]);
                    }

                    // Before handling, validate signature.
                    var fwd_payload = fwd.Payload.ToByteArray();
                    var isSignatureValid = CryptoUtils.ValidateDilithiumSignature(fwd_src_pub_key, fwd_payload, fwd.Signature.ToByteArray());
                    if (!isSignatureValid)
                    {
                        nodeContext.Logger?.LogWarning("Discarding corrupt forward intended for {DestinationThumbprint}.", CryptoUtils.BytesToHex(fwd.DstIdentityThumbprint));
                        return true;
                    }

                    return await HandleMessage(nodeContext, fwd_src_pub_key, fwd.Payload, cancellationToken);

                    // The sender provided no public key, so it is unverified
                    //return await HandleMessage(nodeContext, null, fwd.Payload, cancellationToken);
            }
        }
        else if (envelopePayload.DirectedMessage != null)
        {
            var dm = envelopePayload.DirectedMessage;
            return await HandleDirectedMessage(nodeContext, dm, thumbnailSignatureCache, cancellationToken);
        }
        else
        {
            nodeContext.Logger?.LogError("Unsupported envelope payload received from {PeerShortName} ({RemoteEndPoint}. Closing.", PeerShortName, RemoteEndPoint);
            return false;
        }
    }

    #region Handle EnvelopePayload types
    private bool HandleErrorMessage(
        NodeContext nodeContext,
        ErrorMessage em)
    {
        nodeContext.Logger?.LogDebug("ERROR RECEIVED FROM {PeerShortName} ({RemoteEndPoint}): {ErrorMessage}", PeerShortName, RemoteEndPoint, em.Message);
        return true;
    }

    private async Task<bool> HandleDirectedMessage(
        NodeContext nodeContext,
        DirectedMessage dm,
        ConcurrentDictionary<string,
        ImmutableArray<byte>> thumbnailSignatureCache,
        CancellationToken cancellationToken)
    {
        nodeContext.Logger?.LogDebug("DM RECEIVED FROM {PeerShortName} ({RemoteEndPoint}): {PayloadType}", PeerShortName, RemoteEndPoint, dm.Payload.TypeUrl);
        //MessageUtils.Dump(dm, nodeContext.Logger);

        var isSenderVerifiable = thumbnailSignatureCache.TryGetValue(CryptoUtils.BytesToHex(dm.SrcIdentityThumbprint), out ImmutableArray<byte> sourceIdentityPublicKey);
        var dm_payload = dm.Payload.ToByteArray();
        var isSignatureValid = isSenderVerifiable && CryptoUtils.ValidateDilithiumSignature(sourceIdentityPublicKey, dm_payload, dm.Signature.ToByteArray());

        // Is this destined for me?
        if (!Enumerable.SequenceEqual(nodeContext.NodeIdentityKeyPublicThumbprint, dm.DstIdentityThumbprint))
        {
            // It is NOT destined for me.  But can I be useful and verify the signature so I do not forward corruption?
            if (isSenderVerifiable && !isSignatureValid)
            {
                nodeContext.Logger?.LogWarning("Discarding corrupt message intended for {DestinationThumbprint}.", CryptoUtils.BytesToHex(dm.DstIdentityThumbprint));
                return true;
            }

            // Okay, it was NOT destined for me, but it was not wrapped as a forward.
            // This peer must be confused, or it has intentionally done this to get me to cough up my table of immediate neighbors.
            // Which I will do.  TODO Consider security implications vs. utility of this behavior.
            nodeContext.Logger?.LogInformation("Misdirected direct message intended for {DestinationThumbprint} from {PeerShortName}; returning unreachable error.", CryptoUtils.BytesToHex(dm.DstIdentityThumbprint), PeerShortName);
            var neighbors = nodeContext.GetNeighborThumbprints();
            var err = new ErrorDestinationUnreachable
            {
                UnreachableIdentityThumbprint = dm.DstIdentityThumbprint
            };
            err.NeighborThumbprints.AddRange(neighbors.Select(n => ByteString.CopyFrom([.. n])));

            var err_payload = IdentityPublicKeyThumbprint == null
                ? null
                : nodeContext.PrepareEnvelopePayload(IdentityPublicKeyThumbprint.Value, err);
            if (err_payload != null)
                await SendEnvelope(nodeContext, PrepareEnvelope(nodeContext, err_payload), cancellationToken);
            return true;
        }

        // Is the signature verifiable?
        if (!isSenderVerifiable)
        {
            nodeContext.Logger?.LogError("Discarding message signed with unknown signature purportedly from {SourceThumbprint} intended for me.", CryptoUtils.BytesToHex(dm.SrcIdentityThumbprint));
            return false;
        }

        if (!isSignatureValid)
        {
            nodeContext.Logger?.LogError("Discarding message with invalid signature from {SourceThumbprint} intended for me.", CryptoUtils.BytesToHex(dm.SrcIdentityThumbprint));
            return false;
        }

        return await HandleMessage(nodeContext, sourceIdentityPublicKey, dm.Payload, cancellationToken);
    }
    #endregion 

    #region Handle Messages
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
        var encapsulatedKey = ComputeSessionSharedKeyFromSynAndGetCipherText([.. syn.SessionPubKey.ToByteArray()]);

        // This peer's identity key was received in Syn.
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer at {RemoteEndPoint} should have an empty identity public key field at Syn time!");

        var id_pub_key_bytes = syn.IdPubKey.ToByteArray();
        IdentityPublicKey = id_pub_key_bytes.ToImmutableArray();
        IdentityPublicKeyThumbprint = SHA256.HashData(id_pub_key_bytes).ToImmutableArray();
        PeerName = CryptoUtils.BytesToHex(IdentityPublicKeyThumbprint);
        PeerShortName = $"{PeerName[..8]}";

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

        var bytes_to_send = message.ToByteArray();
        await stream.WriteAsync(bytes_to_send, cancellationToken);
        BytesSent += (ulong)bytes_to_send.Length;
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
        PeerShortName = $"{PeerName[..8]}";

        //nodeContext.Logger?.LogCritical("SESSION KEY HASH {PeerShortName} ({peer.RemoteEndPoint})={SessionKeyHash}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey!)));
        return true;
    }

    internal async Task<bool> HandleMessage(NodeContext nodeContext, ImmutableArray<byte> verifiedSourceIdentityPubKey, Any message, CancellationToken cancellationToken)
    {

        switch (message)
        {
            case Any any when any.Is(ConsoleAlert.Descriptor):
                nodeContext.Logger?.LogCritical("CONSOLE ALERT from {PeerShortName} ({RemoteEndPoint}): {Contents}", PeerShortName, RemoteEndPoint, any.Unpack<ConsoleAlert>().Message);
                return true;
            case Any any when any.Is(ErrorDestinationUnreachable.Descriptor):
                {
                    var err = any.Unpack<ErrorDestinationUnreachable>();
                    nodeContext.Logger?.LogInformation("ErrorDestinationUnreachable from {PeerShortName} ({RemoteEndPoint}): {NeighborCount} neighbors provided", PeerShortName, RemoteEndPoint, err.NeighborThumbprints.Count);
                    await nodeContext.WriteLineToUserAsync($"DESTINATION UNREACHABLE FOR {CryptoUtils.BytesToHex(err.UnreachableIdentityThumbprint)} VIA {PeerShortName}", cancellationToken);
                    return true;
                }
            case Any any when any.Is(Ping.Descriptor):
                return await HandlePing(nodeContext, verifiedSourceIdentityPubKey, any.Unpack<Ping>(), cancellationToken);
            case Any any when any.Is(Pong.Descriptor):
                return await HandlePong(nodeContext, any.Unpack<Pong>(), cancellationToken);
            default:
                nodeContext.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported forwarded message type {PayloadType}", PeerShortName, RemoteEndPoint, message.TypeUrl);
                return false;
        }
    }

    private async Task<bool> HandlePing(NodeContext nodeContext, ImmutableArray<byte> verifiedSourceIdentityPubKey, Ping ping, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verifiedSourceIdentityPubKey);
        ArgumentNullException.ThrowIfNull(ping);

        var pong = new Pong
        {
            Identifier = ping.Identifier,
            Sequence = ping.Sequence,
            Payload = ping.Payload
        };

        nodeContext.Logger?.LogDebug("Replying PONG {LocalEndPoint}->{RemoteEndPoint}", LocalEndPoint, RemoteEndPoint);

        var returnThumbprint = SHA256.HashData([..verifiedSourceIdentityPubKey]);
        var msg = nodeContext.PrepareEnvelopePayload([.. returnThumbprint], pong);
        if (msg == null)
        {
            nodeContext.Logger?.LogError("Unknown error preparing PONG envelope; aborting response.");
            return false;
        }

        var envelope = PrepareEnvelope(nodeContext, msg);
        await SendEnvelope(nodeContext, envelope, cancellationToken);
        return true;
    }

    private async Task<bool> HandlePong(NodeContext nodeContext, Pong pong, CancellationToken cancellationToken)
    {
        nodeContext.Logger?.LogInformation("PONG from {PeerShortName} ({RemoteEndPoint}): {Contents}", PeerShortName, RemoteEndPoint, $"id={pong.Identifier} seq={pong.Sequence}");
        await nodeContext.WriteLineToUserAsync($"{pong.CalculateSize()} bytes from {RemoteEndPoint}: seq={pong.Sequence}", cancellationToken);
        return true;
    }
    #endregion

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

    public Envelope PrepareEnvelope(NodeContext nodeContext, IMessage message)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(message);
        if (message is ErrorMessage em)
            return PrepareEnvelopeInternal(nodeContext, em: em);
        if (message is ForwardedMessage fm)
            return PrepareEnvelopeInternal(nodeContext, fm: fm);
        if (message is DirectedMessage dm)
            return PrepareEnvelopeInternal(nodeContext, dm: dm);

        nodeContext.Logger?.LogError("Unsupported envelope payload {Type}", message.GetType().FullName);
        throw new ArgumentException($"Unsupported envelope payload type {message.GetType().FullName}");
    }

    public Envelope PrepareEnvelope(NodeContext nodeContext, ErrorMessage message)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(message);
        return PrepareEnvelopeInternal(nodeContext, em: message);
    }

    public Envelope PrepareEnvelope(NodeContext nodeContext, ForwardedMessage message)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(message);
        return PrepareEnvelopeInternal(nodeContext, fm: message);
    }

    public Envelope PrepareEnvelope(NodeContext nodeContext, DirectedMessage message)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(message);
        return PrepareEnvelopeInternal(nodeContext, dm: message);
    }

    private Envelope PrepareEnvelopeInternal(NodeContext nodeContext, ErrorMessage? em = null, ForwardedMessage? fm = null, DirectedMessage? dm = null)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);

        var envelope_payload = new EnvelopePayload();
        if (em != null)
            envelope_payload.ErrorMessage = em;
        else if (fm != null)
            envelope_payload.ForwardedMessage = fm;
        else if (dm != null)
            envelope_payload.DirectedMessage = dm;
        else
            throw new ArgumentException("Incompatible message type provided for envelope payload", nameof(dm));

        var envelope_payload_bytes = envelope_payload.ToByteArray();
        if (envelope_payload_bytes == null || envelope_payload_bytes.Length == 0)
            throw new ArgumentException("Could not serialize envelope payload to byte array");

        if (SessionSharedKey == null || SessionSharedKey.Value.Length == 0)
        {
            nodeContext.Logger?.LogError("Session key is not established with peer {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);
            throw new InvalidOperationException($"Session key is not established with peer {PeerShortName} ({RemoteEndPoint})");
        }

        byte[] nonce = new byte[12];
        byte[] plain_text = envelope_payload_bytes;
        byte[] cipher_text = new byte[plain_text.Length];
        byte[] tag = new byte[16];
        byte[]? associated_data = null;
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

        if (SessionPublicKey == null)
        {
            throw new InvalidOperationException("SessionPublicKey not set, but I am the one sending the syn!");
        }

        var message = new Syn
        {
            ProtVer = Node.PROTOCOL_VERSION,
            SessionPubKey = ByteString.CopyFrom([.. SessionPublicKey.Value]),
            IdPubKey = ByteString.CopyFrom([.. nodeContext.NodeIdentityKeyPublicBytes])
        };

        var bytes_to_send = message.ToByteArray();
        await Client.GetStream().WriteAsync(bytes_to_send, cancellationToken);
        BytesSent += (ulong)bytes_to_send.Length;
    }

    public async Task<bool> SendEnvelope(NodeContext nodeContext, Envelope envelope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(envelope);

        var bytes_to_send = envelope.ToByteArray();
        try
        {
            await Client.GetStream().WriteAsync(bytes_to_send, cancellationToken);
            BytesSent += (ulong)bytes_to_send.Length;
            return true;
        }
        catch (Exception ex)
        {
            nodeContext.Logger?.LogError(ex, "Unable to write envelope bytes. Closing.");
            Client.Close();
            return false;
        }
    }

    public async Task<bool> SendPing(NodeContext nodeContext, ImmutableArray<byte>? targetThumbprint, CancellationToken cancellationToken)
    {
        var ping = new Ping
        {
            Identifier = 1,
            Sequence = 1,
            Payload = ByteString.Empty
        };

        var ping_destination = targetThumbprint == null ? IdentityPublicKeyThumbprint!.Value : targetThumbprint.Value;
        var msg = nodeContext.PrepareEnvelopePayload(ping_destination, ping);
        bool success = msg != null;
        if (success)
        {
            var env = PrepareEnvelope(nodeContext, msg!);
            success = await SendEnvelope(nodeContext, env, cancellationToken);
        }

        if (success)
        {
            if (targetThumbprint == null)
                nodeContext.Logger?.LogInformation("PING to {PeerShortName} ({RemoteEndPoint}): {Contents}", PeerShortName, RemoteEndPoint, $"id={ping.Identifier} seq={ping.Sequence}");
            else
                nodeContext.Logger?.LogInformation("PING to {PeerShortName} ({RemoteEndPoint}) destined for {DestinationThumbprint}: {Contents}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(targetThumbprint.Value), $"id={ping.Identifier} seq={ping.Sequence}");
        }
        else
        {
            nodeContext.Logger?.LogError("ERROR sending PING to {PeerShortName} ({RemoteEndPoint})", PeerShortName, RemoteEndPoint);
        }
        return success;
    }
}

