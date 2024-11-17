using System.Collections.Immutable;
using Google.Protobuf;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.Common;

public interface IAppContext
{
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
}