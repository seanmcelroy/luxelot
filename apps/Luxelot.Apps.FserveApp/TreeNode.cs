using System.Collections.Immutable;

namespace Luxelot.Apps.FserveApp;

public class TreeNode
{
    public static readonly TreeNode EmptyRoot = new()
    {
        Name = "/",
        Count = 0,
        DescendentCount = 0,
        Size = uint.MaxValue,
        DescendentSize = uint.MaxValue,
        Children = null,
        LastModified = null
    };

    public required string Name { get; init; }
    public required uint Size { get; init; }
    public required DateTimeOffset? LastModified { get; init; }
    public required uint DescendentSize { get; set; }
    public required uint Count { get; init; }
    public required uint DescendentCount { get; set; }
    public required ImmutableDictionary<string, TreeNode>? Children { get; init; }
}