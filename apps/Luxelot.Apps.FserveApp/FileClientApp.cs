using System.Collections.Immutable;
using System.Reflection;
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
    public List<IConsoleCommand> Commands { get; init; } = [];

    public string Name => "Fserve Client";

    public string? InteractiveCommand => "fs";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;

        // Load Console Commands
        var consoleCommandTypes = Assembly.GetExecutingAssembly().GetTypes().Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IConsoleCommand).FullName) == 0)).ToArray();
        foreach (var consoleCommandType in consoleCommandTypes)
        {
            var objApp = Activator.CreateInstance(consoleCommandType, true);
#pragma warning disable IDE0019 // Use pattern matching
            var consoleCommand = objApp as IConsoleCommand;
#pragma warning restore IDE0019 // Use pattern matching
            if (consoleCommand == null)
            {
                appContext.Logger?.LogError("Unable to load console command {TypeName}", consoleCommandType.FullName);
                continue;
            }

            Commands.Add(consoleCommand);
            consoleCommand.OnInitialize(appContext);
            appContext.Logger?.LogInformation("Loaded console command '{CommandName}' ({TypeName})", consoleCommand.Command, consoleCommandType.FullName);
        }

        Reset(false);
    }

    public async Task OnActivate(CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        await appContext.SendConsoleMessage($"{Name} {version}", cancellationToken);
    }

    private void Reset(bool generateKeypair)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        ServerThumbprint = null;
        if (generateKeypair) // Avoid expensive keygen at initialize, b/c this may not be used.
        {
            var (publicKeyBytes, privateKeyBytes) = appContext.GenerateKyberKeyPair();
            SessionPublicKey = publicKeyBytes;
            SessionPrivateKey = privateKeyBytes;
        }
        else {
            SessionPublicKey = null;
            SessionPrivateKey = null;
        }
        SessionSharedKey = null;// Computed after AuthChannelResponse received
    }

    public async Task<(bool handled, bool success)> TryInvokeCommand(string command, string[] words, CancellationToken cancellationToken)
    {
        var appCommand = Commands.FirstOrDefault(cc => string.Compare(cc.Command, command, StringComparison.InvariantCultureIgnoreCase) == 0);
        if (appCommand == null)
            return (false, false);
        var success = await appCommand.Invoke(words, cancellationToken);
        return (true, success);
    }

    public async Task<bool> SendAuthChannelBegin(ImmutableArray<byte> destinationThumbprint, string username, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destinationThumbprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        Reset(true);

        ServerThumbprint = destinationThumbprint;
        Principal = Encoding.UTF8.GetBytes(username).ToImmutableArray();

        return await appContext.SendMessage(destinationThumbprint, new AuthChannelBegin
        {
            ProtVer = FserveApp.FS_PROTOCOL_VERSION,
            SessionPubKey = ByteString.CopyFrom([.. SessionPublicKey!]),
        }, cancellationToken);
    }

    public async Task<bool> SendListRequest(string? directory, CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (ServerThumbprint == null || SessionSharedKey == null)
        {
            appContext.Logger?.LogInformation("Listing failed, no connection to a server");
            await appContext.SendConsoleMessage($"Not connected to an fserve.", cancellationToken);
            return false;
        }

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new ListRequest
            {
                Directory = directory ?? string.Empty,
                Pattern = string.Empty // TODO
            },
            SessionSharedKey.Value);

        return await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken);
    }

    public async Task<bool> SendChangeDirectoryRequest(string directory, CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (ServerThumbprint == null || SessionSharedKey == null)
        {
            appContext.Logger?.LogInformation("Change directory failed, no connection to a server");
            await appContext.SendConsoleMessage($"Not connected to an fserve.", cancellationToken);
            return false;
        }

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new ChangeDirectoryRequest
            {
                Directory = directory,
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
        SessionSharedKey = appContext.GenerateChrystalsKyberDecryptionKey(SessionPrivateKey.Value, [.. acr.CipherText], appContext.Logger);

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

        switch (status.Operation)
        {
            case Operation.Cd:
                await appContext.SendConsoleMessage($"CD command {(status.StatusCode >= 200 && status.StatusCode <= 299 ? "successful" : "failed")}: {status.StatusMessage}", cancellationToken);
                return true;
            default:
                await appContext.SendConsoleMessage($"FSERVE Status: {status.StatusCode} {status.StatusMessage}", cancellationToken);
                return true;
        }

    }

    public async Task<bool> HandleListResponse(IRequestContext requestContext, ListResponse listResponse, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(listResponse);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        using var scope = appContext.Logger?.BeginScope(nameof(HandleListResponse));

        if (ServerThumbprint == null)
        {
            appContext.Logger?.LogError("Received from {SourceThumbprint}, but not currently connected. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("Received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }
        appContext.Logger?.LogInformation("Received from {SourceThumbprint}: {StatusCode} {StatusMessage}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), listResponse.StatusCode, listResponse.StatusMessage);

        await appContext.SendConsoleMessage($"Listing for '{listResponse.Directory}':    {listResponse.StatusCode}", cancellationToken);
        foreach (var result in listResponse.Results)
        {
            await appContext.SendConsoleMessage($"{result.Name} {result.Size}", cancellationToken);
        }
        await appContext.SendConsoleMessage("End of List", cancellationToken);
        return true;
    }

    public async Task<bool> HandleUserInput(string input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(input);

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        var sb = new StringBuilder();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                sb.AppendLine($"\r\n{InteractiveCommand}> Command List");
                var built_in_cmds = new string[] { "version", "exit", "cd", "login", "list" };
                sb.AppendLine($"{InteractiveCommand}> {built_in_cmds.Order().Aggregate((c, n) => $"{c}\r\n{InteractiveCommand}> {n}")}");
                sb.AppendLine($"{InteractiveCommand}> End of Command List");
                await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
                return true;

            case "version":
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                await appContext.SendConsoleMessage($"{Name} v{version}", cancellationToken);
                return true;

            case "login":
                var fsLogin = new LoginCommand();
                fsLogin.OnInitialize(appContext);
                return await fsLogin.Invoke(words, cancellationToken);

            case "cd":
            case "chdir":
                var fsCd = new ChangeDirectoryCommand();
                fsCd.OnInitialize(appContext);
                return await fsCd.Invoke(words, cancellationToken);

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