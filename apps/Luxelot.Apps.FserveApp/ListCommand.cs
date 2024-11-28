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

    public async Task<(bool success, string? errorMessage)> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 1 && words.Length != 2)
            return (false, "Command requires zero or one argument, the optional directory to list.");

        var directory = words.Length == 1 ? null : words[1];

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            return (false, "Internal error.");
        }

        return (await fileClientApp.SendListRequest(directory, cancellationToken), null);
    }
}