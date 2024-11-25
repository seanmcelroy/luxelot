namespace Luxelot.Apps.FserveApp.Config;

public sealed class MountsConfig
{
    public bool HideEmptyDirectories { get; set; }
    public Dictionary<string, MountPoint>? Mounts { get; set; }
}
