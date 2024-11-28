using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class ChangeLocalDirectoryCommand : IConsoleCommand
{
    internal const string LOCAL_WORKING_DIRECTORY = "LOCAL_DIR";
    private IAppContext? appContext;

    public string FullCommand => "fslcd";

    public string InteractiveCommand => "lcd";

    public string[] InteractiveAliases => ["lchdir"];

    public string ShortHelp => "Changes the current directory on the local client";

    public string Usage => "lcd <DIRECTORY>";

    public string Example => "lcd ~/Downloads";

    internal static string GetDefaultDownloadDirectory()
    {
        var inferredDownloadDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return Directory.Exists(inferredDownloadDir)
            ? inferredDownloadDir
            : Environment.GetFolderPath(Environment.SpecialFolder.Personal);
    }

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;


        appContext.AddOrUpdate(LOCAL_WORKING_DIRECTORY, GetDefaultDownloadDirectory());
    }

    public async Task<(bool success, string? errorMessage)> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 1 && words.Length != 2)
            return (false, "Command requires one argument, the directory to select.");

        var directory = words.Length == 1 ? GetDefaultDownloadDirectory() : words[1..].Aggregate((c, n) => $"{c} {n}");

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            return (false, "Internal error.");
        }

        if (!Directory.Exists(directory))
            return (false, "No such directory '{directory}'");

        try
        {
            var dir = Path.GetFullPath(directory);
            appContext.AddOrUpdate(LOCAL_WORKING_DIRECTORY, dir);
            return (true, "Local directory changed to: '{dir}'");
        }
        catch (Exception ex)
        {
            appContext.Logger?.LogWarning(ex, "Unable to parse directory '{Directory} into a full path.", directory);
            return (false, $"Unrecognized directory: '{directory}'");
        }
    }
}