using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class ListCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string FullCommand => "fslist";

    public string InteractiveCommand => "list";

    public string[] InteractiveAliases => ["ls", "dir"];

    public string ShortHelp => "Lists the current directory, or the one optionally specified";

    public string Usage => "list [DIRECTORY]";

    public string Example => "list (OR) list /public/pictures";


    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<bool> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 1 && words.Length != 2)
        {
            await appContext.SendConsoleMessage($"FSLIST command requires zero or one argument, the optional directory to list.", cancellationToken);
            return false;
        }

        var directory = words.Length == 1 ? null : words[1];

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            await appContext.SendConsoleMessage($"Internal error.", cancellationToken);
            return false;
        }

        return await fileClientApp.SendListRequest(directory, cancellationToken);
    }
}