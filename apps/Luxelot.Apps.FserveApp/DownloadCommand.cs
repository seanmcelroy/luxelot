using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class DownloadCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string FullCommand => "fsdownload";

    public string InteractiveCommand => "download";

    public string[] InteractiveAliases => ["dl"];

    public string ShortHelp => "Downloads a prepared file, either by its filename or the download ticket.  Optionally, if the file has multiple chunks, the chunk number can be specified";

    public string Usage => "download <FILENAME|TICKET> [CHUNK_NUMBER]";

    public string Example => "download readme.txt";


    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<bool> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 2 && words.Length != 3)
        {
            await appContext.SendConsoleMessage($"Command requires one or two arguments, the file to download and optionally the chunk number of the file to retrieve.", cancellationToken);
            return false;
        }

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            await appContext.SendConsoleMessage($"Internal error.", cancellationToken);
            return false;
        }

        uint? chunkNumber = null;
        if (words.Length == 3 && uint.TryParse(words[3], out uint chunkNumber2))
            chunkNumber = chunkNumber2;

        return await fileClientApp.SendDownloadRequests(words[1], chunkNumber, cancellationToken);
    }
}