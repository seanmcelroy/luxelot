using System.Collections.Immutable;
using System.Net;

namespace Luxelot.Apps.Common;

public interface IRequestContext
{
    public string PeerShortName { get; }
    public EndPoint LocalEndPoint { get; }
    public EndPoint RemoteEndPoint { get; }

    public ImmutableArray<byte> RequestSourceThumbprint { get; }
    public string RequestSourceThumbprintHex { get => Convert.ToHexString(RequestSourceThumbprint.AsSpan()); }
}