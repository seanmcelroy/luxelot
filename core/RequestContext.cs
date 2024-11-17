using System.Collections.Immutable;
using System.Net;
using Google.Protobuf;
using Luxelot.Apps.Common;

namespace Luxelot;

public class RequestContext : IRequestContext
{
    public required string PeerShortName { get; init; }

    public required EndPoint LocalEndPoint { get; init; }

    public required EndPoint RemoteEndPoint { get; init; }

    public required ImmutableArray<byte> RequestSourceThumbprint { get; init; }

    public Task<bool> Reply(IMessage message, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}