using System.Collections.Immutable;

namespace Luxelot.Apps.FileServerApp;

public class ClientConnection
{
    public ImmutableArray<byte>? SessionPublicKey { get; private set; }
    public ImmutableArray<byte>? SessionSharedKey { get; private set; }


}