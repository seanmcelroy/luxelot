namespace Luxelot.Apps.FserveApp.Config;

public sealed class MountPoint
{
    public required string RealPath { get; set; }
    public required ushort EffectiveMode { get; set; }
    public required string[] ExcludedPatterns { get; set; }
    public required int RecursiveDepth {get;set;} = int.MaxValue;
}