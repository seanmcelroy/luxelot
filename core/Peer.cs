using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.App.Common.Messages;
using Luxelot.Apps.Common;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot;

internal class Peer : IDisposable
{
    private bool disposed = false;

    public string Name { get; private set; } = "<Unset>";
    public string ShortName { get; private set; } = "<Unset>";
    public ImmutableArray<byte>? IdentityPublicKey { get; private set; }
    public ImmutableArray<byte>? IdentityPublicKeyThumbprint { get; private set; }
    public ImmutableArray<byte>? SessionPublicKey { get; init; }
    private ImmutableArray<byte>? SessionPrivateKey { get; init; }
    public ImmutableArray<byte>? SessionSharedKey { get; private set; }
    private TcpClient Client { get; init; }

    // State
    public PeerState State { get; private set; } = PeerState.CLOSED;
    public DateTimeOffset LastActivity { get; set; } = DateTimeOffset.Now;

    // Metrics
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

    internal static Peer CreatePeerFromAccept(TcpClient tcpClient)
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

    internal static async Task<Peer?> CreatePeerAndConnect(IPEndPoint endPoint, ILogger logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endPoint);

        TcpClient peerTcpClient = new();
        try
        {
            await peerTcpClient.ConnectAsync(endPoint, cancellationToken);
        }
        catch (SocketException sex)
        {
            logger.LogError(sex, "Unable to connect to {RemoteEndPoint}", endPoint);
            return null;
        }

        var (publicKeyBytes, privateKeyBytes) = CryptoUtils.GenerateKyberKeyPair(logger);
        var peer = new Peer(peerTcpClient)
        {
            SessionPublicKey = publicKeyBytes,
            SessionPrivateKey = privateKeyBytes,
            SessionSharedKey = null // Computed after Ack received
        };
        return peer;
    }

    internal async Task<bool> HandleInputAsync(
        NodeContext nodeContext,
        ConcurrentDictionary<string, ImmutableArray<byte>> thumbprintSignatureCache,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thumbprintSignatureCache);
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
            size = await Client.GetStream().ReadAtLeastAsync(buffer, 1, cancellationToken: cancellationToken);
            BytesReceived += (ulong)size;
            //nodeContext.Logger?.LogTrace("HandleInputAsync read {BytesReceived} bytes", size);
            LastActivity = DateTimeOffset.Now;
        }
        catch (EndOfStreamException ex)
        {
            nodeContext.Logger?.LogWarning(ex, "End of stream from peer {PeerShortName} ({RemoteEndPoint}) could be processed. Closing.", ShortName, RemoteEndPoint);
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
            nodeContext.Logger?.LogError(ex, "Invalid Envelope from {PeerShortName} ({RemoteEndPoint}) could not be parsed. Closing.", ShortName, RemoteEndPoint);
            Client.Close();
            return false;
        }

        // Decrypt envelope contents.
        //MessageUtils.Dump(envelope, nodeContext.Logger);
        //Console.WriteLine($"SESSION KEY HASH={CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey))}");

        byte[] envelope_plain_text;
        try {
            envelope_plain_text = CryptoUtils.DecryptEnvelopeInternal(envelope, SessionSharedKey.Value, nodeContext.Logger);
        }
        catch
        {
            // Swallow.  Anything worth logging is handled by DecryptEnvelopeInternal() before rethrowing to here.
            Client.Close();
            return false;
        }

        EnvelopePayload envelopePayload;
        try
        {
            envelopePayload = EnvelopePayload.Parser.ParseFrom(envelope_plain_text, 0, envelope_plain_text.Length);
        }
        catch (InvalidProtocolBufferException ex)
        {
            nodeContext.Logger?.LogError(ex, "Invalid EnvelopePayload from {PeerShortName} ({RemoteEndPoint}) could not be parsed. Closing.", ShortName, RemoteEndPoint);
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

            if (!fwd.IsValid())
            {
                nodeContext.Logger?.LogTrace("Peer {PeerShortName} forwarded invalid forward message, ignoring: ForwardId={ForwardId}", ShortName, fwd.ForwardId);
                return true;
            }

            nodeContext.Logger?.LogDebug("FORWARD FROM {PeerShortName} ({RemoteEndPoint}) intended for {DestinationThumbprint}: ForwardId={ForwardId}", ShortName, RemoteEndPoint, DisplayUtils.BytesToHex(fwd.DstIdentityThumbprint), fwd.ForwardId);

            // Have I seen this message before?
            if (nodeContext.RegisterForwardId(fwd.ForwardId))
            {
                nodeContext.Logger?.LogTrace("Peer {PeerShortName} forwarded known message, ignoring: ForwardId={ForwardId}", ShortName, fwd.ForwardId);
                return true;
            }

            // Is the forwarded message purportedly from ME?  That's bogus, close client.
            if (fwd.SrcIdentityThumbprint.SequenceEqual(nodeContext.NodeIdentityKeyPublicThumbprint))
            {
                nodeContext.Logger?.LogError("Peer {PeerShortName} forwarded message to me purportedly from myself: ForwardId={ForwardId}", ShortName, fwd.ForwardId);
                Client.Close();
                return false;
            }

            // Is the forwarded message destined for the sender?  That's a boomerang loop, close dumb client.
            if (IdentityPublicKeyThumbprint.HasValue
                && fwd.DstIdentityThumbprint.SequenceEqual(IdentityPublicKeyThumbprint.Value))
            {
                nodeContext.Logger?.LogError("Peer {PeerShortName} forwarded message to me destined for itself: ForwardId={ForwardId}", ShortName, fwd.ForwardId);
                Client.Close();
                return false;
            }

            // Is the forwarded message destined for a node OTHER THAN me?
            if (!fwd.DstIdentityThumbprint.SequenceEqual(nodeContext.NodeIdentityKeyPublicThumbprint))
            {
                if (fwd.Ttl <= 1)
                {
                    nodeContext.Logger?.LogWarning("Forwarded message TTL via {PeerShortName} has expired: ForwardId={ForwardId}", ShortName, fwd.ForwardId);
                    return true;
                }

                if (IdentityPublicKeyThumbprint != null &&
                    !Enumerable.SequenceEqual(fwd.SrcIdentityThumbprint, IdentityPublicKeyThumbprint.Value))
                {
                    // This is from a node which is not this peer, so remember this later on for routing.
                    nodeContext.AdvisePeerPathToIdentity(this, [.. fwd.SrcIdentityThumbprint.ToByteArray()]);
                }

                await nodeContext.RelayForwardMessage(fwd, IdentityPublicKeyThumbprint, cancellationToken);
                return true;
            }

            // This is a forwarded message for me.            
            nodeContext.Logger?.LogTrace("FORWARDED MESSAGE RECEIVED VIA {PeerShortName} ({RemoteEndPoint}): ForwardId={ForwardId}", ShortName, RemoteEndPoint, fwd.ForwardId);
            switch (fwd.Payload)
            {
                case Any any when any.Is(ErrorMessage.Descriptor):
                    var err = any.Unpack<ErrorMessage>();
                    return HandleErrorMessage(nodeContext, err);
                case Any any when any.Is(DirectedMessage.Descriptor):
                    var dm = any.Unpack<DirectedMessage>();
                    return await HandleDirectedMessage(nodeContext, dm, thumbprintSignatureCache, cancellationToken);
                case Any any when any.Is(ForwardedMessage.Descriptor):
                    nodeContext.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Forwarded message payload is another forwarded message.  Discarding.", ShortName, RemoteEndPoint);
                    Client.Close();
                    return true;
                default:
                    // This is the normal case, it's a forwarded message of some other type.

                    if (fwd.SrcIdentityThumbprint == null)
                    {
                        nodeContext.Logger?.LogWarning("Discarding forward with missing src intended for {DestinationThumbprint}.", DisplayUtils.BytesToHex(fwd.DstIdentityThumbprint));
                        return true;
                    }

                    // If we are aware of the public key of the origin, then validate the forwarded message.
                    ImmutableArray<byte> fwd_origin_pub_thumbprint = [.. fwd.SrcIdentityThumbprint];
                    var cacheKey = DisplayUtils.BytesToHex(fwd_origin_pub_thumbprint);
                    if (thumbprintSignatureCache.TryGetValue(cacheKey, out ImmutableArray<byte> fwd_origin_pub_key))
                    {
                        var fwd_payload = fwd.Payload.ToByteArray();
                        var isSignatureValid = CryptoUtils.ValidateDilithiumSignature(fwd_origin_pub_key, fwd_payload, fwd.Signature.ToByteArray());
                        if (!isSignatureValid)
                        {
                            nodeContext.Logger?.LogWarning("Discarding corrupt forward intended for {DestinationThumbprint}.", DisplayUtils.BytesToHex(fwd.DstIdentityThumbprint));
                            return true;
                        }
                    }

                    return await HandleMessage(nodeContext, fwd_origin_pub_thumbprint, fwd.Payload, cancellationToken);

                    // The sender provided no public key, so it is unverified
                    //return await HandleMessage(nodeContext, null, fwd.Payload, cancellationToken);
            }
        }
        else if (envelopePayload.DirectedMessage != null)
        {
            var dm = envelopePayload.DirectedMessage;
            return await HandleDirectedMessage(nodeContext, dm, thumbprintSignatureCache, cancellationToken);
        }
        else
        {
            nodeContext.Logger?.LogError("Unsupported envelope payload received from {PeerShortName} ({RemoteEndPoint}. Closing.", ShortName, RemoteEndPoint);
            return false;
        }
    }

    #region Handle EnvelopePayload types
    private bool HandleErrorMessage(
        NodeContext nodeContext,
        ErrorMessage em)
    {
        nodeContext.Logger?.LogDebug("ERROR RECEIVED FROM {PeerShortName} ({RemoteEndPoint}): {ErrorMessage}", ShortName, RemoteEndPoint, em.Message);
        return true;
    }

    private async Task<bool> HandleDirectedMessage(
        NodeContext nodeContext,
        DirectedMessage dm,
        ConcurrentDictionary<string,
        ImmutableArray<byte>> thumbprintSignatureCache,
        CancellationToken cancellationToken)
    {
        nodeContext.Logger?.LogDebug("DM RECEIVED FROM {PeerShortName} ({RemoteEndPoint}): {PayloadType}", ShortName, RemoteEndPoint, dm.Payload.TypeUrl);
        //MessageUtils.Dump(dm, nodeContext.Logger);

        var isSenderVerifiable = thumbprintSignatureCache.TryGetValue(DisplayUtils.BytesToHex(dm.SrcIdentityThumbprint), out ImmutableArray<byte> sourceIdentityPublicKey);
        var dm_payload = dm.Payload.ToByteArray();
        var isSignatureValid = isSenderVerifiable && CryptoUtils.ValidateDilithiumSignature(sourceIdentityPublicKey, dm_payload, dm.Signature.ToByteArray());

        // Is this destined for me?
        if (!Enumerable.SequenceEqual(nodeContext.NodeIdentityKeyPublicThumbprint, dm.DstIdentityThumbprint))
        {
            // It is NOT destined for me.  But can I be useful and verify the signature so I do not forward corruption?
            if (isSenderVerifiable && !isSignatureValid)
            {
                nodeContext.Logger?.LogWarning("Discarding corrupt message intended for {DestinationThumbprint}.", DisplayUtils.BytesToHex(dm.DstIdentityThumbprint));
                return true;
            }

            // Okay, it was NOT destined for me, but it was not wrapped as a forward.
            // This peer must be confused, or it has intentionally done this to get me to cough up my table of immediate neighbors.
            // Which I will do.  TODO Consider security implications vs. utility of this behavior.
            nodeContext.Logger?.LogInformation("Misdirected direct message intended for {DestinationThumbprint} from {PeerShortName}; returning unreachable error.", DisplayUtils.BytesToHex(dm.DstIdentityThumbprint), ShortName);
            var neighbors = nodeContext.GetNeighborThumbprints();
            var err = new ErrorDestinationUnreachable
            {
                UnreachableIdentityThumbprint = dm.DstIdentityThumbprint
            };
            err.NeighborThumbprints.AddRange(neighbors.Select(n => ByteString.CopyFrom([.. n])));

            var err_payload = IdentityPublicKeyThumbprint == null
                ? null
                : nodeContext.PrepareEnvelopePayload(IdentityPublicKeyThumbprint.Value, [.. dm.SrcIdentityThumbprint.ToByteArray()], err);
            if (err_payload != null)
                await SendEnvelope(PrepareEnvelope(err_payload, nodeContext.Logger), nodeContext.Logger, cancellationToken);
            return true;
        }

        // Is the signature verifiable?
        if (!isSenderVerifiable)
        {
            nodeContext.Logger?.LogError("Discarding message signed with unknown signature purportedly from {SourceThumbprint} intended for me.", DisplayUtils.BytesToHex(dm.SrcIdentityThumbprint));
            return false;
        }

        if (!isSignatureValid)
        {
            nodeContext.Logger?.LogError("Discarding message with invalid signature from {SourceThumbprint} intended for me.", DisplayUtils.BytesToHex(dm.SrcIdentityThumbprint));
            return false;
        }

        ImmutableArray<byte> srcThumbprint = [..dm.SrcIdentityThumbprint.ToByteArray()];
        return await HandleMessage(nodeContext, srcThumbprint, dm.Payload, cancellationToken);
    }
    #endregion 

    #region Handle Messages
    internal async Task<bool> HandleSyn(NodeContext nodeContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);

        State = PeerState.SYN_RECEIVED;

        // We expect a Syn (with a public key).  Calculate the Kyber cipher text and send back an Ack.
        var stream = Client.GetStream();
        if (!stream.CanRead || !stream.CanWrite)
            return false;

        int size = 4168; // Special case since we know exact field sizes for Syn.
        var buffer = new byte[size];
        try
        {
            await stream.ReadExactlyAsync(buffer, 0, size, cancellationToken: cancellationToken);
            BytesReceived += (ulong)size;
            LastActivity = DateTimeOffset.Now;
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
        if (SessionSharedKey != null) {
            nodeContext.Logger?.LogError("Session shared key already calculated processing Syn from {RemoteEndPoint}! Closing.", RemoteEndPoint);
            Client.Close();
            return false;            
        }
        var (encapsulatedKey, sessionSharedKey) = CryptoUtils.ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey([.. syn.SessionPubKey.ToByteArray()]);
        SessionSharedKey = sessionSharedKey;

        // This peer's identity key was received in Syn.
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer at {RemoteEndPoint} should have an empty identity public key field at Syn time!");

        var id_pub_key_bytes = syn.IdPubKey.ToByteArray();
        IdentityPublicKey = id_pub_key_bytes.ToImmutableArray();
        IdentityPublicKeyThumbprint = SHA256.HashData(id_pub_key_bytes).ToImmutableArray();
        Name = DisplayUtils.BytesToHex(IdentityPublicKeyThumbprint);
        ShortName = $"{Name[..8]}";

        nodeContext.Logger?.LogDebug("ID Key for {PeerShortName} ({RemoteEndPoint}) is thumbprint {Thumbprint}", ShortName, RemoteEndPoint, DisplayUtils.BytesToHex(IdentityPublicKeyThumbprint));
        //nodeContext.Logger?.LogCritical("SESSION KEY HASH {PeerShortName} ({peer.RemoteEndPoint})={SessionKeyHash}", PeerShortName, RemoteEndPoint, DisplayUtils.BytesToHex(SHA256.HashData(SessionSharedKey!)));
        nodeContext.Logger?.LogDebug("Sending Ack to peer {PeerShortName} ({RemoteEndPoint})", ShortName, RemoteEndPoint);

        var message = new Ack
        {
            ProtVer = Node.NODE_PROTOCOL_VERSION,
            CipherText = ByteString.CopyFrom(encapsulatedKey),
            // Now provide our own identity key in the response Ack
            IdPubKey = ByteString.CopyFrom([.. nodeContext.NodeIdentityKeyPublicBytes]),
        };

        var bytes_to_send = message.ToByteArray();
        await stream.WriteAsync(bytes_to_send, cancellationToken);
        BytesSent += (ulong)bytes_to_send.Length;
        LastActivity = DateTimeOffset.Now;
        return true;
    }

    internal async Task<bool> HandleAck(NodeContext nodeContext, CancellationToken cancellationToken)
    {
        // Here we will get what we need to compute the shared secret.
        // At the start of this, we should NOT have any identity key, as that comes in the Ack.
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer {ShortName} already has an identity public key by the time this Ack was recieved.");

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
            LastActivity = DateTimeOffset.Now;
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
            if (ack.IdPubKey == null || ack.IdPubKey.Length != Constants.KYBER_PUBLIC_KEY_LEN)
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

        // Shared Key
        if (SessionSharedKey != null)
            throw new InvalidOperationException("Shared key already computed!");
        if (SessionPrivateKey == null)
            throw new InvalidOperationException("Private key not set!");
        SessionSharedKey = CryptoUtils.GenerateChrystalsKyberDecryptionKey(SessionPrivateKey.Value, [.. ack.CipherText.ToByteArray()]);
        if (IdentityPublicKey != null)
            throw new InvalidOperationException($"Peer {Name} should have an empty identity public key field at Ack time!");

        var id_pub_key_bytes = ack.IdPubKey.ToByteArray();
        IdentityPublicKey = id_pub_key_bytes.ToImmutableArray();
        IdentityPublicKeyThumbprint = SHA256.HashData(id_pub_key_bytes).ToImmutableArray();
        Name = DisplayUtils.BytesToHex(IdentityPublicKeyThumbprint);
        ShortName = $"{Name[..8]}";
        State = PeerState.ESTABLISHED;

        //nodeContext.Logger?.LogCritical("SESSION KEY HASH {PeerShortName} ({peer.RemoteEndPoint})={SessionKeyHash}", PeerShortName, RemoteEndPoint, CryptoUtils.BytesToHex(SHA256.HashData(SessionSharedKey!)));
        return true;
    }

    internal async Task<bool> HandleMessage(NodeContext nodeContext, ImmutableArray<byte> sourceThumbprint, Any message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nodeContext);
        ArgumentNullException.ThrowIfNull(sourceThumbprint);
        ArgumentNullException.ThrowIfNull(message);

        if (sourceThumbprint.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(sourceThumbprint), $"Source thumbprint should be {Constants.THUMBPRINT_LEN} bytes long but was {sourceThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        switch (message)
        {
            case Any any when any.Is(ConsoleAlert.Descriptor):
                nodeContext.Logger?.LogCritical("CONSOLE ALERT from {PeerShortName} ({RemoteEndPoint}): {Contents}", ShortName, RemoteEndPoint, any.Unpack<ConsoleAlert>().Message);
                return true;
            case Any any when any.Is(ErrorDestinationUnreachable.Descriptor):
                {
                    var err = any.Unpack<ErrorDestinationUnreachable>();
                    nodeContext.Logger?.LogInformation("ErrorDestinationUnreachable from {PeerShortName} ({RemoteEndPoint}): {NeighborCount} neighbors provided", ShortName, RemoteEndPoint, err.NeighborThumbprints.Count);
                    await nodeContext.WriteLineToUserAsync($"DESTINATION UNREACHABLE FOR {DisplayUtils.BytesToHex(err.UnreachableIdentityThumbprint)} VIA {ShortName}", cancellationToken);
                    return true;
                }
            //case Any any when any.Is(Ping.Descriptor):
            //    return await HandlePing(nodeContext, verifiedSourceIdentityPubKey, any.Unpack<Ping>(), cancellationToken);
            //case Any any when any.Is(Pong.Descriptor):
            //    return await HandlePong(nodeContext, any.Unpack<Pong>(), cancellationToken);
            default:
                var requestContext = new RequestContext
                {
                    PeerShortName = ShortName,
                    LocalEndPoint = LocalEndPoint!,
                    RemoteEndPoint = RemoteEndPoint!,
                    RequestSourceThumbprint = sourceThumbprint
                };
                var (handled, success) = await nodeContext.TryHandleMessage(requestContext, message, cancellationToken);
                if (handled)
                    return true;

                nodeContext.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported forwarded message type {PayloadType}", ShortName, RemoteEndPoint, message.TypeUrl);
                return false;
        }
    }
    #endregion

    public void CloseInternal()
    {
        State = PeerState.CLOSING;
        Client.Close();
        State = PeerState.CLOSED;
    }

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

    public Envelope PrepareEnvelope(IMessage message, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message is ErrorMessage em)
            return PrepareEnvelopeInternal(em: em, logger: logger);
        if (message is ForwardedMessage fm)
            return PrepareEnvelopeInternal(fm: fm, logger: logger);
        if (message is DirectedMessage dm)
            return PrepareEnvelopeInternal(dm: dm, logger: logger);

        logger?.LogError("Unsupported envelope payload {Type}", message.GetType().FullName);
        throw new ArgumentException($"Unsupported envelope payload type {message.GetType().FullName}");
    }

    public Envelope PrepareEnvelope(ErrorMessage message, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(message);
        return PrepareEnvelopeInternal(em: message, logger: logger);
    }

    public Envelope PrepareEnvelope(ForwardedMessage message, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(message);
        return PrepareEnvelopeInternal(fm: message, logger: logger);
    }

    public Envelope PrepareEnvelope(DirectedMessage message, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(message);
        return PrepareEnvelopeInternal(dm: message, logger: logger);
    }

    private Envelope PrepareEnvelopeInternal(ErrorMessage? em = null, ForwardedMessage? fm = null, DirectedMessage? dm = null, ILogger? logger = null)
    {
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
            logger?.LogError("Session key is not established with peer {PeerShortName} ({RemoteEndPoint})", ShortName, RemoteEndPoint);
            throw new InvalidOperationException($"Session key is not established with peer {ShortName} ({RemoteEndPoint})");
        }

        return CryptoUtils.EncryptEnvelopeInternal(envelope_payload_bytes, SessionSharedKey.Value, logger);
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
            ProtVer = Node.NODE_PROTOCOL_VERSION,
            SessionPubKey = ByteString.CopyFrom([.. SessionPublicKey.Value]),
            IdPubKey = ByteString.CopyFrom([.. nodeContext.NodeIdentityKeyPublicBytes])
        };

        var bytes_to_send = message.ToByteArray();
        await Client.GetStream().WriteAsync(bytes_to_send, cancellationToken);
        BytesSent += (ulong)bytes_to_send.Length;
        LastActivity = DateTimeOffset.Now;

        State = PeerState.SYN_SENT;
    }

    public async Task<bool> SendEnvelope(Envelope envelope, ILogger? logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        var bytes_to_send = envelope.ToByteArray();
        try
        {
            await Client.GetStream().WriteAsync(bytes_to_send, cancellationToken);
            BytesSent += (ulong)bytes_to_send.Length;
            //logger?.LogTrace("SendEnvelope sent {BytesSent} bytes", bytes_to_send.Length);
            LastActivity = DateTimeOffset.Now;
            return true;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Unable to write envelope bytes. Closing.");
            Client.Close();
            return false;
        }
    }
}

