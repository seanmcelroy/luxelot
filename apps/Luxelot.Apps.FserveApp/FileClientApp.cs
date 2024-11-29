using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Data;
using System.Reflection;
using System.Security.Cryptography;
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

    /// <summary>
    /// Chunks that have been downlaoded, keyed by (download ticket, chunk seq) with the file as the value.
    /// </summary>
    private readonly ConcurrentDictionary<(string, uint), FileInfo> ChunkDownloads = [];

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

    public async Task<(bool handled, bool success, string? errrorMessage)> TryInvokeCommand(string command, string[] words, CancellationToken cancellationToken)
    {
        var appCommand = Commands.FirstOrDefault(cc => string.Compare(cc.FullCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0);
        if (appCommand == null)
            return (false, false, null);
        var (success, errorMessage) = await appCommand.Invoke(words, cancellationToken);
        return (true, success, errorMessage);
    }

    public async Task<bool> SendAuthChannelBegin(ImmutableArray<byte> destinationThumbprint, string username, CancellationToken cancellationToken)
    {
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

    public async Task<(bool success, string? errorMessage)> SendChangeDirectoryRequest(string directory, CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (ServerThumbprint == null || SessionSharedKey == null)
        {
            appContext.Logger?.LogInformation("Change directory failed, no connection to a server");
            return (false, "Not connected to an fserve.");
        }

        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new ChangeDirectory
            {
                Directory = directory,
            },
            SessionSharedKey.Value);

        return (await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken), null);
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
            appContext.Logger?.LogError("FSERVE AuthChannelResponse received from {SourceThumbprint}, but not currently connected. Ignoring.", requestContext.RequestSourceThumbprintHex);
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("FSERVE AuthChannelResponse received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", requestContext.RequestSourceThumbprintHex, DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }

        // Shared Key
        if (SessionSharedKey != null)
            throw new InvalidOperationException("Shared key already computed!");
        if (SessionPrivateKey == null)
            throw new InvalidOperationException("Private key not set!");
        SessionSharedKey = appContext.GenerateChrystalsKyberDecryptionKey(SessionPrivateKey.Value, [.. acr.CipherText], appContext.Logger);

        appContext.Logger?.LogInformation("FSERVE AuthChannelResponse received from {SourceThumbprint}. Session shared key established.", requestContext.RequestSourceThumbprintHex);

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
            appContext.Logger?.LogError("FSERVE Status received from {SourceThumbprint}, but not currently connected. Ignoring.", requestContext.RequestSourceThumbprintHex);
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("FSERVE Status received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", requestContext.RequestSourceThumbprintHex, DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }
        appContext.Logger?.LogInformation("FSERVE Status received from {SourceThumbprint}: {StatusCode} {StatusMessage}", requestContext.RequestSourceThumbprintHex, status.StatusCode, status.StatusMessage);

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
            appContext.Logger?.LogError("Received from {SourceThumbprint}, but not currently connected. Ignoring.", requestContext.RequestSourceThumbprintHex);
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("Received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", requestContext.RequestSourceThumbprintHex, DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }
        appContext.Logger?.LogInformation("Received from {SourceThumbprint}: {StatusCode} {StatusMessage}", requestContext.RequestSourceThumbprintHex, listResponse.StatusCode, listResponse.StatusMessage);

        var sb = new StringBuilder();
        sb.AppendLine($"Listing for '{listResponse.Directory}': {listResponse.StatusCode}");
        if (listResponse.Results.Count > 0)
        {
            var size_len = listResponse.Results.Max(r => r.Size.ToString().Length);
            foreach (var result in listResponse.Results)
            {
                sb.AppendFormat("{0} {1:MMM dd HH:mm} {2} {3}\r\n", DisplayUtils.UnixFileModeToString(result.Mode, result.IsDirectory), result.Modified.ToDateTimeOffset(), result.Size.ToString().PadLeft(size_len), result.Name);
            }
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
            appContext.Logger?.LogError("Received from {SourceThumbprint}, but not currently connected. Ignoring.", requestContext.RequestSourceThumbprintHex);
            return true;
        }

        if (!Enumerable.SequenceEqual(requestContext.RequestSourceThumbprint, ServerThumbprint))
        {
            appContext.Logger?.LogError("Received from {SourceThumbprint}, but currently connected to {ServerThumbprint}. Ignoring.", requestContext.RequestSourceThumbprintHex, DisplayUtils.BytesToHex(ServerThumbprint));
            return true;
        }
        appContext.Logger?.LogInformation("Received from {SourceThumbprint}: Download ready for {Filename} via ticket {Ticket}", requestContext.RequestSourceThumbprintHex, dr.File, dr.Ticket);

        List<ChunkInfo> remoteChunks =
        [
            .. dr.Chunks.Select(chunk => new ChunkInfo
            {
                ServerThumbprint = ServerThumbprint.Value,
                FileName = dr.File,
                DownloadTicket = dr.Ticket,
                FileSize = dr.Size,
                FileHash = [.. dr.Hash],
                ChunkCount = dr.ChunkCount,
                ChunkSequence = chunk.Seq,
                ChunkSize = (uint)chunk.Size,
                ChunkHash = [.. chunk.Hash]
            }),
        ];

        // Did we get all the chunks?
        if (remoteChunks.Count != dr.ChunkCount)
        {
            appContext.Logger?.LogError("Received incomplete chunk list from {SourceThumbprint} for ticket {Ticket}. Ignoring.", requestContext.RequestSourceThumbprintHex, dr.Ticket);
            return true;
        }
        if (Enumerable.Range(1, (int)dr.ChunkCount).Sum() != remoteChunks.Sum(c => c.ChunkSequence))
        {
            appContext.Logger?.LogError("Inconsistent chunk sequence list from {SourceThumbprint} for ticket {Ticket}. Ignoring.", requestContext.RequestSourceThumbprintHex, dr.Ticket);
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

        if (ServerThumbprint == null || SessionSharedKey == null)
        {
            appContext.Logger?.LogInformation("Prepare download failed, no connection to a server");
            await appContext.SendConsoleMessage($"Not connected to an fserve.", cancellationToken);
            return false;
        }

        // Were we expecting this chunk?
        var clientKvp = ClientChunks.FirstOrDefault(cc =>
            string.CompareOrdinal(cc.Key, cr.DownloadTicket) == 0
            && cc.Value.SingleOrDefault(c => c.ChunkSequence == cr.ChunkSeq && c.ChunkSize == cr.ChunkSize) != default);

        if (clientKvp.Equals(default(KeyValuePair<string, ChunkInfo[]>)))
        {
            appContext.Logger?.LogError("No client chunk profiled for ticket {Ticket} seq {ChunkSequence}. Ignoring.", cr.DownloadTicket, cr.ChunkSeq);
            return true;
        }

        // Get the chunk entry, with a concurrency check
        var clientChunk = clientKvp.Value.SingleOrDefault(c => c.ChunkSequence == cr.ChunkSeq
            && c.ChunkSize == cr.ChunkSize);
        if (clientChunk == default)
        {
            appContext.Logger?.LogError("No client chunk profiled for ticket {Ticket} seq {ChunkSequence}. Ignoring.", cr.DownloadTicket, cr.ChunkSeq);
            return true;
        }

        // Have we already downloaded it?
        if (ChunkDownloads.TryGetValue((cr.DownloadTicket, cr.ChunkSeq), out FileInfo? chunkFileInfo)
            && chunkFileInfo.Exists)
        {
            appContext.Logger?.LogError("Chunk already downloaded for ticket {Ticket} seq {ChunkSequence} at '{Path}'. Ignoring.", cr.DownloadTicket, cr.ChunkSeq, chunkFileInfo.FullName);
            return true;
        }

        // Does the chunk size and hash match?
        {
            if (cr.Payload.Span.Length != clientChunk.ChunkSize)
            {
                appContext.Logger?.LogError("Chunk size does not match for ticket {Ticket} seq {ChunkSequence} (downloaded {ChunkSizeActual} but expected {ChunkSizeExpected}). Ignoring.", cr.DownloadTicket, cr.ChunkSeq, cr.Payload.Span.Length, clientChunk.ChunkSize);
                return true;
            }

            byte[] chunkHash = new byte[32];
            if (!SHA256.TryHashData(cr.Payload.Span, chunkHash, out _))
            {
                appContext.Logger?.LogError("Unable to hash chunk for ticket {Ticket} seq {ChunkSequence}. Ignoring.", cr.DownloadTicket, cr.ChunkSeq);
                return true;
            }
            if (!Enumerable.SequenceEqual(
                clientChunk.ChunkHash,
                chunkHash))
            {
                appContext.Logger?.LogError("Chunk hash does not match for ticket {Ticket} seq {ChunkSequence}. Ignoring.", cr.DownloadTicket, cr.ChunkSeq);
                return true;
            }
        }

        // Save chunk
        var chunkFilename = Path.GetTempFileName();
        chunkFileInfo = new FileInfo(chunkFilename);
        await File.WriteAllBytesAsync(chunkFilename, cr.Payload.ToByteArray(), cancellationToken);
        ChunkDownloads.TryAdd((cr.DownloadTicket, cr.ChunkSeq), chunkFileInfo);
        await appContext.SendConsoleMessage($"Downloaded chunk {cr.ChunkSeq}/{clientChunk.ChunkCount} ({cr.ChunkSize} bytes)", cancellationToken);

        // Is that the final chunk?
        if (ChunkDownloads.Keys.Count(cd => string.CompareOrdinal(cd.Item1, cr.DownloadTicket) == 0)
            == clientChunk.ChunkCount)
        {
            // Reassemble all chunks into the file.
            var reassembledFilename = Path.GetTempFileName();
            using (var fs = File.OpenWrite(reassembledFilename))
            {
                for (uint i = 1; i <= clientChunk.ChunkCount; i++)
                {
                    if (!ChunkDownloads.TryGetValue((cr.DownloadTicket, i), out FileInfo? chunkFi))
                    {
                        appContext.Logger?.LogError("Chunk metadata inconsistent in memory for ticket {Ticket} seq {ChunkSequence}. Ignoring.", cr.DownloadTicket, cr.ChunkSeq);
                        return true;
                    }

                    var chunkBytes = await File.ReadAllBytesAsync(chunkFi.FullName, cancellationToken);
                    await fs.WriteAsync(chunkBytes, cancellationToken);
                }
            }

            // Validate total file hash
            var fileOk = true;
            {
                var fiReassembled = new FileInfo(reassembledFilename);
                if (fiReassembled.Exists && (ulong)fiReassembled.Length != clientChunk.FileSize)
                {
                    fileOk = false;
                    appContext.Logger?.LogError("File size does not match for ticket {Ticket} (downloaded {FileSizeActual} but expected {FileSizeExpected}). Ignoring.", cr.DownloadTicket, fiReassembled.Length, clientChunk.FileSize);
                    if (fiReassembled.Exists)
                        fiReassembled.Delete();
                    // Don't return.. go through clean-up.
                }
            }

            if (fileOk)
            {
                using (var fs = File.OpenRead(reassembledFilename))
                {
                    byte[] fileHash = new byte[32];
                    await SHA256.HashDataAsync(fs, fileHash, cancellationToken);
                    if (!Enumerable.SequenceEqual(
                        clientChunk.FileHash,
                        fileHash))
                    {
                        fileOk = false;
                        appContext.Logger?.LogError("File hash does not match for ticket {Ticket}. Ignoring.", cr.DownloadTicket);
                        fs.Close();
                        File.Delete(reassembledFilename);
                        // Don't return.. go through clean-up.
                    }
                }
            }

            string destinationPath = string.Empty;
            if (fileOk)
            {
                var destinationFileName = Path.GetFileName(clientKvp.Value[0].FileName);
                if (!appContext.TryGetStateValue(ChangeLocalDirectoryCommand.LOCAL_WORKING_DIRECTORY, out string? lcd))
                {
                    lcd = ChangeLocalDirectoryCommand.GetDefaultDownloadDirectory();
                }
                destinationPath = Path.Combine(lcd!, destinationFileName);
                while (File.Exists(destinationPath))
                {
                    var directoryName = Path.GetDirectoryName(destinationPath)!;
                    var fileName = Path.GetFileNameWithoutExtension(destinationPath)!;
                    var ext = Path.GetExtension(destinationPath);
                    destinationPath = Path.Combine(directoryName, $"{fileName} copy{ext}");
                }
                File.Move(reassembledFilename, destinationPath);
            }

            // Clear from the 'ready to download' list
            if (!ClientChunks.TryRemove(clientKvp))
            {
                // Concurrency check
                appContext.Logger?.LogError("No client chunk currently profiled for ticket {Ticket} seq {ChunkSequence}. Ignoring.", cr.DownloadTicket, cr.ChunkSeq);
                return true;
            }

            // Clear chunk downloads
            for (uint i = 1; i <= clientChunk.ChunkCount; i++)
            {
                if (ChunkDownloads.TryGetValue((cr.DownloadTicket, i), out FileInfo? chunkFi))
                {
                    if (chunkFi.Exists)
                        chunkFi.Delete();
                    _ = ChunkDownloads.Remove((cr.DownloadTicket, i), out _);
                }
            }

            if (fileOk)
            {
                await appContext.SendConsoleMessage($"Downloaded file to '{destinationPath}'", cancellationToken);
                return true;
            }
        }

        // Not the final chunk
        var frame = FrameUtils.WrapClientFrame(
            appContext,
            new ChunkRequest
            {
                DownloadTicket = cr.DownloadTicket,
                ChunkSeq = cr.ChunkSeq + 1,
            },
            SessionSharedKey.Value);

        await appContext.SendMessage(ServerThumbprint.Value, frame, cancellationToken);
        return true;
    }
    public async Task<HandleUserInputResult> HandleUserInput(string input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(input);

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        if (!appContext.TryGetSingleton(out FileClientApp? ca)
            || ca == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for file client");
            return new HandleUserInputResult
            {
                Success = false,
                ErrorMessage = "Internal error.",
                Command = null
            };
        }

        var sb = new StringBuilder();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                sb.AppendLine($"\r\n{InteractiveCommand}> COMMAND LIST");
                var built_in_cmds = new string[] { "version", "exit" };
                var cmd_len = built_in_cmds.Union(ca.Commands.Select(c => c.InteractiveCommand)).Max(c => c.Length);
                var loaded_cmds = ca.Commands.Select(c => $"{c.InteractiveCommand.PadRight(cmd_len)}: {c.ShortHelp}");
                sb.AppendLine($"{InteractiveCommand}> {built_in_cmds.Union(loaded_cmds).Order().Aggregate((c, n) => $"{c}\r\n{InteractiveCommand}> {n}")}");
                sb.AppendLine($"{InteractiveCommand}> END OF COMMAND LIST").AppendLine();
                await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
                return new HandleUserInputResult
                {
                    Success = true,
                    ErrorMessage = null,
                    Command = null
                };

            case "version":
                var version = Assembly.GetExecutingAssembly().GetName().Version;
                await appContext.SendConsoleMessage($"{Name} app v{version}", cancellationToken);
                return new HandleUserInputResult
                {
                    Success = true,
                    ErrorMessage = null,
                    Command = null
                };

            default:
                // Maybe it's a command this client app loaded?
                var appCommand = ca.Commands.FirstOrDefault(cc =>
                    string.Compare(cc.InteractiveCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0
                    || cc.InteractiveAliases.Any(a => string.Compare(a, command, StringComparison.InvariantCultureIgnoreCase) == 0));

                if (appCommand != null)
                {
                    var (success, errorMessage) = await appCommand.Invoke(words, cancellationToken);
                    return new HandleUserInputResult
                    {
                        Success = success,
                        ErrorMessage = errorMessage,
                        Command = appCommand
                    };
                }

                return new HandleUserInputResult
                {
                    Success = false,
                    ErrorMessage = $"Unknown command '{command.Trim()}'. Type 'exit' to exit this app.",
                    Command = null
                };
        }
    }

    public Task OnDeactivate(CancellationToken cancellationToken)
    {

        return Task.CompletedTask;
    }
}