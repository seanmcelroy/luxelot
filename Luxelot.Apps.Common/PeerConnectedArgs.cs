using System.Collections.Immutable;
using System.Net;

namespace Luxelot.Apps.Common;

public class PeerConnectedArgs(IEnumerable<byte> publicKey, IEnumerable<byte> thumbprint, IPEndPoint remoteEndpoint) : EventArgs
{
    public ImmutableArray<byte> PublicKey { get; init; } = publicKey.ToImmutableArray();
    public ImmutableArray<byte> Thumbprint { get; init; } = thumbprint.ToImmutableArray();
    public IPEndPoint RemoteEndpoint { get; init; } = remoteEndpoint;
}