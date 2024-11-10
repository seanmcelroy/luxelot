using System.Net;

internal record PeerEntry
{
    public Guid Peerid { get; init; } = Guid.NewGuid();
    public required EndPoint RemoteEndpoint { get; init; }
    public required byte[] PublicKey { get; init; }
    public required byte[] PrivateKey { get; init; }
    public required byte[]? SharedKey { get; set; }
    public DateTimeOffset LastActivity { get; set; } = DateTimeOffset.Now;
}