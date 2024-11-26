using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Data;
using System.Reflection;
using System.Text;
using Google.Protobuf;
using Luxelot.Apps.Common;
using Luxelot.Apps.Common.DHT;
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
    internal const string CLIENT_APP_NAME = "Fserve Client";

    private IAppContext? appContext;

    public string Name => CLIENT_APP_NAME;

    public string? InteractiveCommand => "fs";

    public ImmutableArray<byte>? ServerThumbprint { get; private set; }
    public ImmutableArray<byte>? SessionPublicKey { get; private set; }
    private ImmutableArray<byte>? SessionPrivateKey { get; set; }
    public ImmutableArray<byte>? SessionSharedKey { get; private set; }
    public ImmutableArray<byte> Principal { get; set; } = [.. Encoding.UTF8.GetBytes("ANONYMOUS")];
    public List<IConsoleCommand> Commands { get; init; } = [];

    /// <summary>
    /// Chunks available to be downloaded, keyed by the download 'ticket' and the chunks as the key.
    /// </summary>
    private readonly ConcurrentDictionary<string, ChunkInfo[]> ClientChunks = [];

    private (string ticket, uint index)? currentChunkGet = null;

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
            appContext.Logger?.LogInformation("Loaded console command '{CommandName}' ({TypeName})", consoleCommand.FullCommand, consoleCommandType.FullName);
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
        else
        {
            SessionPublicKey = null;
            SessionPrivateKey = null;
        }
        SessionSharedKey = null;// Computed after AuthChannelResponse received
    }

    public async Task<(bool handled, bool success)> TryInvokeCommand(string command, string[] words, CancellationToken cancellationToken)
    {
        var appCommand = Commands.FirstOrDefault(cc => string.Compare(cc.FullCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0);
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
        Principal = [.. Encoding.UTF8.GetBytes(username)];

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
            new ChangeDirectory
            {
                Directory = directory,
            },
            SessionSharedKey.Value);

        return await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken);
    }

    public async Task<bool> SendPrepareDownloadRequest(string file, CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (ServerThumbprint == null || SessionSharedKey == null)
        {
            appContext.Logger?.LogInformation("Prepare download failed, no connection to a server");
            await appContext.SendConsoleMessage($"Not connected to an fserve.", cancellationToken);
            return false;
        }

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new PrepareDownload
            {
                File = file,
                UseEncryption = true,
                UseDirectUdp = false,
            },
            SessionSharedKey.Value);

        return await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken);
    }

    public async Task<bool> SendDownloadRequests(string fileOrTicket, uint? chunkNumber, CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (ServerThumbprint == null || SessionSharedKey == null)
        {
            appContext.Logger?.LogInformation("Download failed, no connection to a server");
            await appContext.SendConsoleMessage($"Not connected to an fserve.", cancellationToken);
            return false;
        }

        // Was a ticket supplied?
        ChunkInfo[] chunks;
        if (ClientChunks.TryGetValue(fileOrTicket, out ChunkInfo[]? value))
            chunks = value;
        else
        {
            // Try to identify it by filename.
            var candidates = ClientChunks
                .Where(cc => cc.Value.All(v => string.Compare(v.FileName, fileOrTicket, StringComparison.OrdinalIgnoreCase) == 0))
                .ToArray();

            if (candidates.Length == 0)
            {
                await appContext.SendConsoleMessage($"No known chunks ready for download with filename or ticket '{fileOrTicket}'.", cancellationToken);
                return false;
            }

            if (candidates.Length > 1)
            {
                await appContext.SendConsoleMessage($"Multiple chunks match the filename '{fileOrTicket}'. Specify a ticket number instead", cancellationToken);
                return false;
            }

            chunks = candidates[0].Value;
        }

        await appContext.SendConsoleMessage($"Starting download of {chunks.Length} chunk(s) from {DisplayUtils.BytesToHex(chunks[0].ServerThumbprint)[..8]}", cancellationToken);

        // Set state for what we are downloading for sequential chunk handling
        currentChunkGet = (chunks[0].DownloadTicket, 1);

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new ChunkRequest
            {
                DownloadTicket = chunks[0].DownloadTicket,
                ChunkSeq = 1,
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

        appContext.TryAddDhtEntry(ServerThumbprint.Value, new NodeEntry { IdentityPublicKey = [.. acr.IdPubKey.ToByteArray()], RemoteEndpoint = null });

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

        var sb = new StringBuilder();
        sb.AppendLine($"Listing for '{listResponse.Directory}':    {listResponse.StatusCode}");
        foreach (var result in listResponse.Results)
        {
            sb.AppendLine($"{result.Name} {result.Size}");
        }
        sb.AppendLine("End of List");
        await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
        return true;
    }

    public async Task<bool> HandleDownloadReady(IRequestContext requestContext, DownloadReady dr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(dr);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        using var scope = appContext.Logger?.BeginScope(nameof(HandleDownloadReady));

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
        appContext.Logger?.LogInformation("Received from {SourceThumbprint}: Download ready for {Filename} via ticket {Ticket}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), dr.File, dr.Ticket);

        List<ChunkInfo> remoteChunks =
        [
            .. dr.Chunks.Select(chunk => new ChunkInfo
            {
                ServerThumbprint = ServerThumbprint.Value,
                FileName = dr.File,
                DownloadTicket = dr.Ticket,
                FileSize = dr.Size,
                FileHash = [.. dr.Hash],
                ChunkSequence = chunk.Seq,
                ChunkSize = (uint)chunk.Size,
                ChunkHash = [.. chunk.Hash]
            }),
        ];

        // Did we get all the chunks?
        if (remoteChunks.Count != dr.ChunkCount)
        {
            appContext.Logger?.LogError("Received incomplete chunk list from {SourceThumbprint} for ticket {Ticket}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), dr.Ticket);
            return true;
        }
        if (Enumerable.Range(1, (int)dr.ChunkCount).Sum() != remoteChunks.Sum(c => c.ChunkSequence))
        {
            appContext.Logger?.LogError("Inconsistent chunk sequence list from {SourceThumbprint} for ticket {Ticket}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), dr.Ticket);
            return true;
        }

        ClientChunks.AddOrUpdate(dr.Ticket, (_) => [.. remoteChunks], (_, _) => [.. remoteChunks]);

        var sb = new StringBuilder();
        sb.AppendLine($"Download ready '{dr.File}': Use ticket {dr.Ticket} to retrieve {dr.ChunkCount} chunks.  Total file size {dr.Size}");
        foreach (var chunk in dr.Chunks)
            sb.AppendLine($"Chunk#{chunk.Seq}: {chunk.Size} bytes, hash={DisplayUtils.BytesToHex(chunk.Hash)[..16]}...");
        sb.AppendLine("End of Download Ready");
        await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
        return true;
    }

    public async Task<bool> HandleChunkResponse(IRequestContext requestContext, ChunkResponse cr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(cr);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        using var scope = appContext.Logger?.BeginScope(nameof(HandleChunkResponse));

        await appContext.SendConsoleMessage(Encoding.UTF8.GetString([.. cr.Payload]), cancellationToken);
        throw new NotSupportedException();
    }
    public async Task<bool> HandleUserInput(string input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(input);

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        if (!appContext.TryGetSingleton(out FileClientApp? ca)
            || ca == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            await appContext.SendConsoleMessage($"Internal error.", cancellationToken);
            return false;
        }

        var sb = new StringBuilder();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                sb.AppendLine($"\r\n{InteractiveCommand}> Command List");
                var built_in_cmds = new string[] { "version", "exit" };
                var loaded_cmds = ca.Commands.Select(c => c.InteractiveCommand);
                sb.AppendLine($"{InteractiveCommand}> {built_in_cmds.Union(loaded_cmds).Order().Aggregate((c, n) => $"{c}\r\n{InteractiveCommand}> {n}")}");
                sb.AppendLine($"{InteractiveCommand}> End of Command List");
                await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
                return true;

            case "version":
                var version = Assembly.GetExecutingAssembly().GetName().Version;
                await appContext.SendConsoleMessage($"{Name} v{version}", cancellationToken);
                return true;

            default:
                // Maybe it's a command this client app loaded?
                var appCommand = ca.Commands.FirstOrDefault(cc =>
                    string.Compare(cc.InteractiveCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0
                    || cc.InteractiveAliases.Any(a => string.Compare(a, command, StringComparison.InvariantCultureIgnoreCase) == 0));
                if (appCommand != null)
                {
                    var success = await appCommand.Invoke(words, cancellationToken);
                    if (success)
                        return true;
                    await appContext.SendConsoleMessage($"ERROR: {appCommand.FullCommand}", cancellationToken);
                }
                else
                    await appContext.SendConsoleMessage($"{InteractiveCommand}> Unknown command {command}. Type 'exit' to exit this app.", cancellationToken);
                return false;
        }
    }

    public Task OnDeactivate(CancellationToken cancellationToken)
    {

        return Task.CompletedTask;
    }
}