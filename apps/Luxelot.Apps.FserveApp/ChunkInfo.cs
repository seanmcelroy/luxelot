using System.Collections.Immutable;

namespace Luxelot.Apps.FserveApp;

public readonly record struct ChunkInfo
{
    public required ImmutableArray<byte> ServerThumbprint { get; init; }

    // File Info
    public required string FileName { get; init; }
    public required string DownloadTicket { get; init; }
    public required ulong FileSize { get; init; }
    public required ImmutableArray<byte> FileHash { get; init; }

    // Chunk Info
    public required uint ChunkSequence { get; init; }
    public required uint ChunkSize { get; init; }
    public required ImmutableArray<byte> ChunkHash { get; init; }

}