using System.Collections.Immutable;
using System.Text;
using Google.Protobuf;
using Luxelot.Apps.Common;
using Luxelot.Apps.FserveApp.Messages;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using static Luxelot.Apps.Common.RegexUtils;

namespace Luxelot.Apps.FserveApp;

/// <summary>
/// This is a simple fserve client app which does not provide for multiple sessions or downloads.
/// 
/// An instance of this class ia a 'client' to another node's fserve.
/// </summary>
public class FileClientApp : IClientApp
{
    private IAppContext? appContext;

    public ImmutableArray<byte>? ServerThumbprint { get; private set; }
    public ImmutableArray<byte>? SessionPublicKey { get; private set; }
    private ImmutableArray<byte>? SessionPrivateKey { get; set; }
    public ImmutableArray<byte>? SessionSharedKey { get; private set; }
    public ImmutableArray<byte>? Principal { get; set; }

    public string Name => "Fserve Client";

    public string InteractiveCommand => "fs";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;

        Reset();
    }

    public async Task OnActivate(CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        await appContext.SendConsoleMessage("fserve client 0.0.1", cancellationToken);
    }

    public void Reset()
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        ServerThumbprint = null;
        var (publicKeyBytes, privateKeyBytes) = appContext.GenerateKyberKeyPair();
        SessionPublicKey = publicKeyBytes;
        SessionPrivateKey = privateKeyBytes;
        SessionSharedKey = null;// Computed after AuthChannelResponse received
    }

    public async Task<bool> SendAuthChannelBegin(ImmutableArray<byte> destinationThumbprint, string username, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destinationThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        Reset();

        ServerThumbprint = destinationThumbprint;
        Principal = Encoding.UTF8.GetBytes(username).ToImmutableArray();

        return await appContext.SendMessage(destinationThumbprint, new AuthChannelBegin
        {
            ProtVer = FserveApp.FS_PROTOCOL_VERSION,
            SessionPubKey = ByteString.CopyFrom([.. SessionPublicKey!]),
        }, cancellationToken);
    }

    public async Task<bool> SendListRequest(CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (ServerThumbprint == null || SessionSharedKey == null) {
            appContext.Logger?.LogInformation("Listing failed, no connection to a server");
            await appContext.SendConsoleMessage($"Not connected to an fserve.", cancellationToken);
            return false;
        }

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new ListRequest
            {
                Directory = string.Empty,
                Pattern = string.Empty
            },
            SessionSharedKey.Value);

        return await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken);
    }

    public async Task<bool> HandleAuthChannelResponse(IRequestContext requestContext, AuthChannelResponse acr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(acr);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        using var scope = appContext.Logger?.BeginScope("FSERVE HandleAuthChannelResponse");

        if (ServerThumbprint == null)
        {
            appContext.Logger?.LogError("FSERVE AuthChannelResponse received from {SourceThumbprint}, but not currently connected. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("FSERVE AuthChannelResponse received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }

        // Shared Key
        if (SessionSharedKey != null)
            throw new InvalidOperationException("Shared key already computed!");
        if (SessionPrivateKey == null)
            throw new InvalidOperationException("Private key not set!");
        SessionSharedKey = appContext.GenerateChrystalsKyberDecryptionKey(SessionPrivateKey.Value, [.. acr.CipherText]);

        //appContext.Logger?.LogCritical("CLIENT FSERV SESSION KEY: {SessionSharedKey}", DisplayUtils.BytesToHex(SessionSharedKey));
        appContext.Logger?.LogInformation("FSERVE AuthChannelResponse received from {SourceThumbprint}. Session shared key established.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));

        appContext.TryAddThumbprintSignatureCache(ServerThumbprint.Value, [.. acr.IdPubKey.ToByteArray()]);

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new AuthUserBegin
            {
                Principal = ByteString.CopyFrom([.. Principal]),
                InitialUserChallengeType = InitialUserChallengeType.None,
                InitialUserChallengeData = ByteString.Empty,
            },
            SessionSharedKey.Value);

        return await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken);
    }

    public async Task<bool> HandleStatus(IRequestContext requestContext, Status status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(status);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        using var scope = appContext.Logger?.BeginScope("FSERVE Status");

        if (ServerThumbprint == null)
        {
            appContext.Logger?.LogError("FSERVE Status received from {SourceThumbprint}, but not currently connected. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("FSERVE Status received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }
        appContext.Logger?.LogInformation("FSERVE Status received from {SourceThumbprint}: {StatusCode} {StatusMessage}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), status.StatusCode, status.StatusMessage);

        await appContext.SendConsoleMessage($"FSERVE Status: {status.StatusCode} {status.StatusMessage}", cancellationToken);
        return true;
    }

    public async Task<bool> HandleUserInput(string input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(input);

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                await appContext.SendConsoleMessage($"\r\n{InteractiveCommand}> Command List\r\n{InteractiveCommand} >", cancellationToken);
                var built_in_cmds = new string[] { "exit", "login", "list"};
                var cmd_string = built_in_cmds.Order()
                    .Aggregate((c, n) => $"{c}\r\n{InteractiveCommand}> {n}");
                await appContext.SendConsoleMessage(cmd_string, cancellationToken);
                await appContext.SendConsoleMessage($"{InteractiveCommand}> End of Command List", cancellationToken);
                return true;

            case "login":
                var fsLogin = new LoginCommand();
                fsLogin.OnInitialize(appContext);
                return await fsLogin.Invoke(words, cancellationToken);

            case "dir":
            case "ls":
            case "list":
                var fsList = new ListCommand();
                fsList.OnInitialize(appContext);
                return await fsList.Invoke(words, cancellationToken);

            default:
                await appContext.SendConsoleMessage($"{InteractiveCommand}> Unknown command {command}. Type 'exit' to exit this app.", cancellationToken);
                return false;
        }
    }
}