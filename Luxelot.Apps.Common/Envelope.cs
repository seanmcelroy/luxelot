namespace Luxelot.Apps.Common;

public readonly ref struct Envelope
{
    public required ReadOnlySpan<byte> Nonce { get; init; }
    public required ReadOnlySpan<byte> Ciphertext { get; init; }
    public required ReadOnlySpan<byte> Tag { get; init; }
    public required ReadOnlySpan<byte> AssociatedData { get; init; }
}