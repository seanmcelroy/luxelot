using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class PrepareCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string InteractiveCommand => "prepare";

    public string[] InteractiveAliases => ["prep"];

    public string ShortHelp => "Prepares a file for download.  This can be retrieved by a subsequent fsdownload command.";

    public string Usage => "prepare <FILE>";

    public string Example => "prepare readme.txt";


    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<(bool success, string? errorMessage)> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 2)
            return (false, "Command requires one argument, the file to prepare for download.");

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            return (false, "Internal error.");
        }

        return (await fileClientApp.SendPrepareDownloadRequest(words[1], cancellationToken), null);
    }
}