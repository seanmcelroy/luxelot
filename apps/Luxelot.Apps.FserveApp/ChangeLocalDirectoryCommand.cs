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

    public async Task<bool> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 1 && words.Length != 2)
        {
            await appContext.SendConsoleMessage($"Command requires one argument, the directory to select.", cancellationToken);
            return false;
        }

        var directory = words.Length == 1 ? GetDefaultDownloadDirectory() : words[1..].Aggregate((c, n) => $"{c} {n}");

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            await appContext.SendConsoleMessage($"Internal error.", cancellationToken);
            return false;
        }

        if (!Directory.Exists(directory))
        {
            await appContext.SendConsoleMessage($"ERROR: No such directory '{directory}'", cancellationToken);
            return true;
        }

        try
        {
            var dir = Path.GetFullPath(directory);
            appContext.AddOrUpdate(LOCAL_WORKING_DIRECTORY, dir);
            await appContext.SendConsoleMessage($"Local directory changed to: '{dir}'", cancellationToken);
            return true;
        }
        catch (Exception ex)
        {
            appContext.Logger?.LogWarning(ex, "Unable to parse directory '{Directory} into a full path.", directory);
            await appContext.SendConsoleMessage($"Unrecognized directory: '{directory}'", cancellationToken);
            return true;
        }
    }
}