using System.Collections.Immutable;
using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class LoginCommand : IConsoleCommand
{
    private IAppContext? appContext;

    public string Command => "fslogin";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public async Task<bool> Invoke(string[] words, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(words);

        if (words.Length != 3)
        {
            await appContext.SendConsoleMessage($"FSLOGIN command requires two arguments: the peer short name OR destination thumbprint to direct the request and a username.", cancellationToken);
            return false;
        }

        ImmutableArray<byte>? ultimateDestinationThumbprint;
        var routingPeerThumbprint = appContext.FindPeerThumbprintByShortName(words[1]);
        if (routingPeerThumbprint != null)
        {
            ultimateDestinationThumbprint = routingPeerThumbprint;
        }
        else
        {
            ultimateDestinationThumbprint = [.. DisplayUtils.HexToBytes(words[1])];
            if (ultimateDestinationThumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            {
                await appContext.SendConsoleMessage($"Invalid THUMBPRINT for the intended recipient.  Thumbprints are {Constants.THUMBPRINT_LEN} bytes.", cancellationToken);
                return false;
            }
        }

        if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp)
            || fileClientApp == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            await appContext.SendConsoleMessage($"Internal error.", cancellationToken);
            return false;
        }

        return await fileClientApp.SendAuthChannelBegin(ultimateDestinationThumbprint.Value, words[2], cancellationToken);
    }
}