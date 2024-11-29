namespace Luxelot.Apps.Common;

public interface INode
{
    public event EventHandler<PeerConnectedArgs>? PeerConnected;
}