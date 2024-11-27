using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class ChangeDirectoryCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string FullCommand => "fscd";

    public string InteractiveCommand => "cd";

    public string[] InteractiveAliases => ["chdir"];

    public string ShortHelp => "Changes the current directory on the server";

    public string Usage => "cd <DIRECTORY>";

    public string Example => "cd /";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<bool> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 2)
        {
            await appContext.SendConsoleMessage($"Command requires one argument, the directory to select.", cancellationToken);
            return false;
        }

        var directory = words.Length == 1 ? "/" : words[1];

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            await appContext.SendConsoleMessage($"Internal error.", cancellationToken);
            return false;
        }

        return await fileClientApp.SendChangeDirectoryRequest(directory, cancellationToken);
    }
}