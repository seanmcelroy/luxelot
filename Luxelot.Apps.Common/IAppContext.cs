using System.Collections.Immutable;
using Google.Protobuf;
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

    public (byte[] encapsulatedKey, ImmutableArray<byte> sessionSharedKey) ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey(ImmutableArray<byte> publicKey);

    public bool TryRegisterSingleton<T>(Func<T> valueFactory) where T : class;

    public bool TryGetSingleton<T>(out T? value) where T : class;
}