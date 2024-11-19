namespace Luxelot.Config;

public sealed class NodeInstance
{
    public required string ListenAddress { get; set; }
    public required ushort PeerPort { get; set; }
    public required ushort UserPort { get; set; }
    public required string[] KnownPeers { get; set; }
}