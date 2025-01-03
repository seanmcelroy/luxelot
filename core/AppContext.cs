using System.Collections.Concurrent;
using System.Collections.Immutable;
using Google.Protobuf;
using Luxelot.Apps.Common;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using System.Diagnostics.CodeAnalysis;

namespace Luxelot;

internal class AppContext : IAppContext
{
    private readonly ConcurrentDictionary<Type, object> Singletons = [];
    private readonly ConcurrentDictionary<string, object> State = [];

    public ImmutableArray<byte> IdentityKeyPublicBytes => Node.IdentityKeyPublicBytes;
    public ImmutableArray<byte> IdentityKeyPublicThumbprint => Node.IdentityKeyPublicThumbprint;

    public required ILogger? Logger { get; init; }

    public required Node Node { private get; init; }


    public ImmutableArray<byte>? FindPeerThumbprintByShortName(string shortName) => Node.FindPeerThumbprintByShortName(shortName);

    private Peer? FindPeerByThumbprint(ImmutableArray<byte> thumbprint) => Node.FindPeerByThumbprint(thumbprint);

    public async Task SendConsoleMessage(string message, CancellationToken cancellationToken) =>
        await Node.WriteLineToUserAsync(message, cancellationToken);

    public async Task<bool> SendMessage(
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (ultimateDestinationThumbprint.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(ultimateDestinationThumbprint), $"Thumbprint should be {Apps.Common.Constants.THUMBPRINT_LEN} bytes long but was {ultimateDestinationThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        var msg = Node.PrepareEnvelopePayload(null, ultimateDestinationThumbprint, message);
        bool success = msg != null;
        if (success)
        {
            var routingPeer = FindPeerByThumbprint(ultimateDestinationThumbprint);
            if (routingPeer != null)
            {
                // We happen to be directly connected.
                if (msg is ForwardedMessage)
                {
                    throw new InvalidOperationException();
                }
                var env = routingPeer.PrepareEnvelope(msg!, Logger);
                success = await routingPeer.SendEnvelope(env, Logger, cancellationToken);
            }
            else
            {
                if (msg is not ForwardedMessage fwd)
                {
                    throw new InvalidOperationException();
                }

                // TODO: Do we know the best place to send this message?
                // if so, set routingPeer to that and send there.

                // TODO: Otherwise, broadcast to all peers
                await Node.InitiateForwardMessage(fwd, Logger, cancellationToken);
            }
        }

        return success;
    }

    public async Task<bool> SendRoutedMessage(
        ImmutableArray<byte> routingPeerThumbprint,
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (routingPeerThumbprint.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(routingPeerThumbprint), $"Thumbprint should be {Apps.Common.Constants.THUMBPRINT_LEN} bytes long but was {routingPeerThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        if (ultimateDestinationThumbprint.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(ultimateDestinationThumbprint), $"Thumbprint should be {Apps.Common.Constants.THUMBPRINT_LEN} bytes long but was {ultimateDestinationThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        if (routingPeerThumbprint.All(b => b == 0x00) &&
            ultimateDestinationThumbprint.Any(b => b != 0x00))
            return false; // We do not allow routed messages to loopback ultimately destined for anything other than loopback

        var routingPeer = FindPeerByThumbprint(routingPeerThumbprint) ?? throw new ArgumentOutOfRangeException(nameof(routingPeerThumbprint), $"Unable to find source-routed peer {routingPeerThumbprint} by its thumbprint");
        var msg = Node.PrepareEnvelopePayload(routingPeerThumbprint, ultimateDestinationThumbprint, message);
        bool success = msg != null;
        if (success)
        {
            var env = routingPeer.PrepareEnvelope(msg!, Logger);
            success = await routingPeer.SendEnvelope(env, Logger, cancellationToken);
        }

        return success;
    }

    public (ImmutableArray<byte> publicKeyBytes, ImmutableArray<byte> privateKeyBytes) GenerateKyberKeyPair() => CryptoUtils.GenerateKyberKeyPair(Logger);

    public (ImmutableArray<byte> encapsulatedKey, ImmutableArray<byte> sessionSharedKey) ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey(ReadOnlySpan<byte> publicKey, ILogger? logger) => CryptoUtils.ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey(publicKey, logger);

    public ImmutableArray<byte> GenerateChrystalsKyberDecryptionKey(ImmutableArray<byte> privateKeyBytes, ReadOnlySpan<byte> encapsulatedKey, ILogger? logger) =>
        CryptoUtils.GenerateChrystalsKyberDecryptionKey(privateKeyBytes, encapsulatedKey, logger);

    public bool TryRegisterSingleton<T>(Func<T> valueFactory) where T : class
    {
        T value = valueFactory.Invoke();
        var actualType = value.GetType();

        if (Singletons.ContainsKey(actualType))
            return false;

        return Singletons.TryAdd(actualType, value);
    }

    public bool TryGetSingleton<T>([NotNullWhen(true)] out T? value) where T : class
    {
        var success = Singletons.TryGetValue(typeof(T), out object? v);
        if (v == null)
        {
            value = null;
            return false;
        }

        value = (T)v;
        return success;
    }

    public Apps.Common.Envelope EncryptEnvelope(byte[] envelope_payload_bytes, ImmutableArray<byte> sessionSharedKey, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(envelope_payload_bytes);

        var envelope = CryptoUtils.EncryptEnvelopeInternal(envelope_payload_bytes, sessionSharedKey, logger);

        return new Apps.Common.Envelope
        {
            Nonce = envelope.Nonce.Span,
            Ciphertext = envelope.Ciphertext.Span,
            Tag = envelope.Tag.Span,
            AssociatedData = envelope.AssociatedData.Span,
        };
    }

    public ReadOnlySpan<byte> DecryptEnvelope(Apps.Common.Envelope envelope, ReadOnlySpan<byte> sessionSharedKey, ILogger? logger) => CryptoUtils.DecryptEnvelopeInternal(envelope, sessionSharedKey, logger);

    public async Task<bool> EnterAppInteractiveMode(string clientAppName, CancellationToken cancellationToken) => await Node.EnterAppInteractiveMode(clientAppName, cancellationToken);

    public async Task<bool> ExitAppInteractiveMode(string clientAppName, CancellationToken cancellationToken) => await Node.ExitAppInteractiveMode(clientAppName, cancellationToken);

    public bool TryGetStateValue<T>(string key, [MaybeNullWhen(false)] out T? value)
    {
        var result = State.TryGetValue(key, out object? value2);
        value = (T?)value2;
        return result;
    }

    public bool TryAddState(string key, [MaybeNullWhen(false)] object value) => State.TryAdd(key, value);

    public bool TryRemoveState(string key, [MaybeNullWhen(false)] out object value) => State.TryRemove(key, out value);

    public void AddOrUpdateState(string key, object value) => _ = State.AddOrUpdate(key, value, (_, _) => value);
}