using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Google.Protobuf;
using Luxelot.Apps.Common.DHT;
using Luxelot.Apps.Common.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.Common;

public interface IAppContext
{
    public ImmutableArray<byte> IdentityKeyPublicBytes { get; }
    public ImmutableArray<byte> IdentityKeyPublicThumbprint { get; }

    public ILogger? Logger { get; }

    public ImmutableArray<byte>? FindPeerThumbprintByShortName(string shortName);

    public Task SendConsoleMessage(string message, CancellationToken cancellationToken);

    public Task<bool> SendMessage(
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage message,
        CancellationToken cancellationToken);

    public Task<bool> SendRoutedMessage(
        ImmutableArray<byte> routingPeerThumbprint,
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage message,
        CancellationToken cancellationToken);

    public (ImmutableArray<byte> publicKeyBytes, ImmutableArray<byte> privateKeyBytes) GenerateKyberKeyPair();

    public (byte[] encapsulatedKey, ImmutableArray<byte> sessionSharedKey) ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey(ImmutableArray<byte> publicKey, ILogger? logger);

    public ImmutableArray<byte> GenerateChrystalsKyberDecryptionKey(ImmutableArray<byte> privateKeyBytes, ImmutableArray<byte> encapsulatedKey, ILogger? logger);

    public Envelope EncryptEnvelope(byte[] envelope_payload_bytes, ImmutableArray<byte> sessionSharedKey, ILogger? logger);

    public byte[]? DecryptEnvelope(Envelope envelope, ImmutableArray<byte> sessionSharedKey, ILogger? logger);

    public bool TryRegisterSingleton<T>(Func<T> valueFactory) where T : class;

    public bool TryAddDhtEntry(ImmutableArray<byte> key, IBucketEntryValue value);

    public bool TryGetSingleton<T>([NotNullWhen(true)] out T? value) where T : class;

    public Task<bool> EnterAppInteractiveMode(string clientAppName, CancellationToken cancellationToken);

    public Task<bool> ExitAppInteractiveMode(string clientAppName, CancellationToken cancellationToken);
}