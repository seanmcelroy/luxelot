using System.Collections.Immutable;
using System.Text;
using Google.Protobuf;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public readonly struct NodeContext(Node node)
{
    public required readonly string NodeShortName { get; init; }
    public required readonly ImmutableArray<byte> NodeIdentityKeyPublicBytes { get; init; }
    public required readonly ILogger? Logger { get; init; }
    private readonly Node _node = node;

    public DirectedMessage PrepareDirectedMessage(ImmutableArray<byte> destinationIdPubKeyThumbprint, IMessage payload)
    {
        return _node.PrepareDirectedMessage(destinationIdPubKeyThumbprint, payload);
    }

    public async Task WriteLineToUserAsync(string message, CancellationToken cancellationToken)
    {
        if (_node.User == null)
            return;
        if (!_node.User.Connected)
            return;
        var stream = _node.User.GetStream();
        if (stream == null)
            return;
        if (!stream.CanWrite)
            return;

        var bytes_to_write = Encoding.UTF8.GetBytes($"{message}\r\n");
        try
        {
            await stream.WriteAsync(bytes_to_write, cancellationToken);
        }
        catch (Exception ex)
        {
            // Swallow.
            Logger?.LogError(ex, "Unable to write message to user. Closing.");
            _node.User.Close();
        }
    }
}