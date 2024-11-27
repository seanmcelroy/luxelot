using System.Collections.Immutable;

namespace Luxelot.Apps.FserveApp;

public class TreeNode
{
    public static readonly TreeNode EmptyRoot = new()
    {
        RelativeName = "/",
        RelativePath = "/",
        AbsolutePath = string.Empty,
        Count = 0,
        DescendentCount = 0,
        Size = uint.MaxValue,
        DescendentSize = uint.MaxValue,
        Children = null,
        LastModified = DateTimeOffset.UtcNow,
        UnixFileMode = UnixFileMode.None,
    };

    public required string RelativeName { get; init; }
    public required string RelativePath { get; init; }
    public required string AbsolutePath { get; init; }
    public required uint Size { get; init; }
    public required DateTimeOffset? LastModified { get; init; }
    public required uint DescendentSize { get; set; }
    public required uint Count { get; init; }
    public required uint DescendentCount { get; set; }
    public required UnixFileMode UnixFileMode { get; init; }
    public required ImmutableDictionary<string, TreeNode>? Children { get; init; }
}