using System.Collections.Immutable;
using Microsoft.Extensions.Logging;

namespace Luxelot;

public readonly struct NodeContext
{
    public required readonly string NodeShortName { get; init; }
    public required readonly ImmutableArray<byte> NodeIdentityKeyPublicBytes { get; init; }
    public required readonly ILogger? Logger { get; init; }
}