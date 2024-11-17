using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Messages;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Luxelot;

public partial class Node
{
    public const uint NODE_PROTOCOL_VERSION = 1;

    private readonly ILogger Logger;
    public required int PeerPort { get; init; }
    public required int UserPort { get; init; }
    public IPEndPoint[]? Phonebook { get; init; }

    // Local state
    private readonly ConcurrentDictionary<TaskEntry, Task> Tasks = [];
    private readonly ConcurrentDictionary<EndPoint, Peer> Peers = [];


    // Network state
    private readonly ConcurrentDictionary<string, ImmutableArray<byte>> ThumbprintSignatureCache = [];
    private readonly ConcurrentDictionary<UInt64, bool> ForwardIds = [];
    private readonly MemoryCache ThumbprintPeerPaths;


    internal TcpClient? User;
    private readonly Mutex UserMutex = new();
    private readonly AsymmetricCipherKeyPair IdentityKeys;
    public readonly ImmutableArray<byte> IdentityKeyPublicBytes;
    public readonly ImmutableArray<byte> IdentityKeyPublicThumbprint;
    public string Name { get; init; }
    public string ShortName { get; init; }

    // Plug-ins
    readonly List<IServerApp> ServerApps = [];
    readonly List<IConsoleCommand> ConsoleCommands = [];
    //readonly List<IClientApp> ClientApps = [];


    public Node(ILoggerFactory loggerFactory, string? shortName)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);

        IdentityKeys = CryptoUtils.GenerateDilithiumKeyPair();
        var identityKeysPublicBytes = ((DilithiumPublicKeyParameters)IdentityKeys.Public).GetEncoded();
        IdentityKeyPublicBytes = [.. identityKeysPublicBytes];
        IdentityKeyPublicThumbprint = [.. SHA256.HashData(identityKeysPublicBytes)];
        Name = DisplayUtils.BytesToHex(IdentityKeyPublicThumbprint);
        if (string.IsNullOrWhiteSpace(shortName))
        {
            ShortName = $"{Name[..8]}...";
            Logger = loggerFactory.CreateLogger($"Node {ShortName}");
        }
        else
        {
            ShortName = shortName;
            Logger = loggerFactory.CreateLogger($"Node {shortName}({Name[..8]}...)");
        }

        Logger.LogInformation("Generated node identity key with thumbprint {Thumbprint}", Name);

        ThumbprintPeerPaths = new(new MemoryCacheOptions { }, loggerFactory);
        Logger.LogInformation("Setup memory caches");
    }

    public async void Main(CancellationToken cancellationToken)
    {
        var nodeContext = new NodeContext(this)
        {
            NodeShortName = ShortName,
            NodeIdentityKeyPublicBytes = IdentityKeyPublicBytes,
            NodeIdentityKeyPublicThumbprint = IdentityKeyPublicThumbprint,
            Logger = Logger,
        };

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Discover plugins
        var assemblyPath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        Logger.LogInformation("Looking for plugins to load in {AssemblyPath}", assemblyPath);
        var potentialPlugins = Directory.EnumerateFiles(assemblyPath, "*App.dll").ToArray();
        foreach (var potentialPlugin in potentialPlugins)
        {
            await using var stream = File.OpenRead(potentialPlugin);
            using var pe = new PEReader(stream);
            if (pe.HasMetadata)
            {
                try
                {
                    // If PEHeaders doesn't throw an exception, it is a valid PEImage
                    _ = pe.PEHeaders.CorHeader;
                    var md = pe.GetMetadataReader();
                    if (md.IsAssembly)
                    {
                        // .NET assembly
                        LoadApp(potentialPlugin);
                    }
                }
                catch (BadImageFormatException)
                {
                    // Swallow.
                }
            }
        }

        Logger.LogTrace("Setting up user listener loop");
        {
            var user_listener_task = Task.Run(async () => await UserListenerTask(nodeContext, cts.Token), cancellationToken);
            var user_listener_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(user_listener_task_entry, user_listener_task);
            Logger.LogTrace("User listener loop is a persistent background worker task {TaskId}", user_listener_task_entry.TaskId);
        }

        Logger.LogTrace("Setting up peer listener loop");
        {
            var peer_listener_task = Task.Run(async () => await PeerListenerTask(nodeContext, cts.Token), cancellationToken);
            var peer_listener_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_listener_task_entry, peer_listener_task);
            Logger.LogTrace("Peer listener loop is a persistent background worker task {TaskId}", peer_listener_task_entry.TaskId);
        }

        Logger.LogTrace("Setting up peer janitor loop");
        {
            var peer_janitor_task = Task.Run(() => PeerJanitorTask(cts.Token), cancellationToken);
            var peer_janitor_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_janitor_task_entry, peer_janitor_task);
            Logger.LogTrace("Peer janitor loop is a persistent background worker task {TaskId}", peer_janitor_task_entry.TaskId);
        }

        Logger.LogTrace("Setting up peer dialer loop");
        {
            var peer_dialer_task = Task.Run(() => PeerDialerTask(nodeContext, cts.Token), cancellationToken);
            var dialer_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(dialer_task_entry, peer_dialer_task);
            Logger.LogTrace("Dialer loop is a persistent background worker task {TaskId}", dialer_task_entry.TaskId);
        }

        Logger.LogTrace("Setting up peer connected input handler loop");
        {
            var peer_handler_task = Task.Run(() => PeerHandleInputTask(nodeContext, cts.Token), cancellationToken);
            var peer_handler_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_handler_task_entry, peer_handler_task);
            Logger.LogTrace("Peer input handler loop is a persistent background worker task {TaskId}", peer_handler_task_entry.TaskId);
        }

        while (!cts.IsCancellationRequested)
        {
            if (Thread.Yield())
                Thread.Sleep(200);

            // Task walk
            int taskQueueSkip = 0;
        task_walk_again:
            int taskIndex = -1;
            foreach (var t in Tasks.Skip(taskQueueSkip))
            {
                taskIndex++;

                if (t.Key.EventType == TaskEventType.PersistentBackgroundWorker)
                {
                    // It better be alive.
                    switch (t.Value.Status)
                    {
                        case TaskStatus.WaitingForActivation:
                        case TaskStatus.Running:
                            {
                                // Fine.
                                break;
                            }
                        default:
                            {
                                Logger.LogError("Persistent background worker is not alive task {TaskId}", t.Key.TaskId);
                                throw new Exception();
                            }
                    }
                    continue;
                }

                // Ignore future scheduled tasks for now.  TODO: Clean-up if they haven't fired for a very long time.
                if (t.Key.NotBefore != null && t.Key.NotBefore > DateTimeOffset.Now)
                    continue;

                // Is it complete?
                switch (t.Value.Status)
                {
                    case TaskStatus.WaitingForActivation:
                    case TaskStatus.Running:
                        {
                            // Fine.
                            break;
                        }
                    case TaskStatus.RanToCompletion:
                        {
                            if (Tasks.TryRemove(t))
                            {
                                Logger.LogTrace("Removed completed task {TaskId}", t.Key.TaskId);
                                taskQueueSkip = taskIndex;
                                goto task_walk_again;
                            }
                            else
                            {
                                // logger.LogError("Cannot remove completed task {TaskId}!", t.Key.TaskId);
                            }

                            break;
                        }
                }
            }
        }
    }

    public void LoadApp(string appPath)
    {
        ArgumentNullException.ThrowIfNull(appPath);

        var appContext = new AppContext()
        {
            Logger = Logger,
            Node = this,
        };

        // Load Apps
        foreach (var path in new string[] { appPath })
        {
            var ass2 = new AppLoader();
            ass2.LoadFromAssemblyPath(path);
            var types = ass2.Assemblies.SelectMany(a => a.ExportedTypes).ToArray();

            // Load Server Apps
            var serverAppTypes = types.Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IServerApp).FullName) == 0)).ToArray();
            foreach (var serverAppType in serverAppTypes)
            {
                var objApp = Activator.CreateInstance(serverAppType, true);
#pragma warning disable IDE0019 // Use pattern matching
                var serverApp = objApp as IServerApp;
#pragma warning restore IDE0019 // Use pattern matching
                if (serverApp == null)
                {
                    Logger.LogError("Unable to load server app {TypeName}", serverAppType.FullName);
                    continue;
                }

                serverApp.OnNodeInitialize(appContext);
                ServerApps.Add(serverApp);
                Logger.LogInformation("Loaded server app {AppName} ({TypeName})", serverApp.Name, serverAppType.FullName);
            }

            // Load Console Commands
            var consoleCommandTypes = types.Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IConsoleCommand).FullName) == 0)).ToArray();
            foreach (var consoleCommandType in consoleCommandTypes)
            {
                var objApp = Activator.CreateInstance(consoleCommandType, true);
#pragma warning disable IDE0019 // Use pattern matching
                var consoleCommand = objApp as IConsoleCommand;
#pragma warning restore IDE0019 // Use pattern matching
                if (consoleCommand == null)
                {
                    Logger.LogError("Unable to load console command {TypeName}", consoleCommandType.FullName);
                    continue;
                }

                ConsoleCommands.Add(consoleCommand);
                consoleCommand.OnInitialize(appContext);
                Logger.LogInformation("Loaded console command '{CommandName}' ({TypeName})", consoleCommand.Command, consoleCommandType.FullName);
            }

            /*/ Load Client Apps
            var clientAppTypes = types.Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IClientApp).FullName) == 0)).ToArray();
            foreach (var clientAppType in clientAppTypes)
            {
                var objApp = Activator.CreateInstance(clientAppType, true);
#pragma warning disable IDE0019 // Use pattern matching
                var clientApp = objApp as IClientApp;
#pragma warning restore IDE0019 // Use pattern matching
                if (clientApp == null)
                {
                    Logger.LogError("Unable to load client app {TypeName}", clientAppType.FullName);
                    continue;
                }

                clientApp.OnNodeInitialize(appContext);
                ClientApps.Add(clientApp);
                Logger.LogInformation("Loaded client app {AppName} ({TypeName})", clientApp.Name, clientAppType.FullName);
            }*/
        }
    }

    #region Tasks
    private async Task UserListenerTask(NodeContext context, CancellationToken cancellationToken)
    {
        try
        {
            using TcpListener user_listener = new(IPAddress.Loopback, UserPort);
            user_listener.Start();
            Logger.LogInformation("Listening for local user commands at {LocalEndpoint}", user_listener.LocalEndpoint);
            while (!cancellationToken.IsCancellationRequested)
            {
                var user = await user_listener.AcceptTcpClientAsync(cancellationToken);
                using (Logger.BeginScope($"User Connection {user.Client?.RemoteEndPoint}"))
                {
                    Logger.LogDebug("New user connection from {RemoteEndPoint}", user.Client?.RemoteEndPoint);

                    var okay = UserMutex.WaitOne(5000); // Wait at most 5 seconds
                    if (!okay)
                    {
                        Logger.LogError("Unable to obtain mutex to accept user connection.");
                        continue;
                    }

                    try
                    {
                        if (User != null)
                        {
                            Logger.LogWarning($"A user connection already exists from {User.Client?.RemoteEndPoint}. Shutting that one down to use this new one from {user.Client?.RemoteEndPoint}");
                            try
                            {
                                await User.GetStream().WriteAsync(Encoding.UTF8.GetBytes($"\r\nUSER CONNECTING FROM {user.Client?.RemoteEndPoint}\r\nGOODBYE.\r\n"), cancellationToken);
                            }
                            catch (Exception ex)
                            {
                                // Swallow exception..
                                Logger.LogTrace(ex, "Unable to send goodbye to replaced user connection");
                            }
                            User.Close();
                            User.Dispose();
                            User = null;
                            continue;
                        }

                        User = user;
                    }
                    finally
                    {
                        UserMutex.ReleaseMutex();
                    }

                    // User input handler loop
                    await User.GetStream().WriteAsync(Encoding.UTF8.GetBytes($"\r\nHELLO.\r\n"), cancellationToken);

                    while (!cancellationToken.IsCancellationRequested && User != null)
                    {
                        var buffer = new byte[1024]; // 1 kb
                        int size = 0;
                        try
                        {
                            size = await User.GetStream().ReadAtLeastAsync(buffer, 1, cancellationToken: cancellationToken);
                        }
                        catch (EndOfStreamException)
                        {
                            // Swallow.
                            Logger.LogInformation("User disconnected from console {RemoteEndPoint}. Closing.", User.Client?.RemoteEndPoint);
                            User.Close();
                            User.Dispose();
                            User = null;
                            continue;
                        }

                        var input = Encoding.UTF8.GetString(buffer, 0, size);
                        await HandleUserInput(context, input, cancellationToken);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Exception in peer listener loop");
            throw;
        }
    }
    private async Task PeerListenerTask(NodeContext context, CancellationToken cancellationToken)
    {
        try
        {
            using TcpListener peer_listener = new(IPAddress.Any, PeerPort);
            peer_listener.Start();
            Logger.LogInformation("Listening for peers at {LocalEndpoint}", peer_listener.LocalEndpoint);
            while (!cancellationToken.IsCancellationRequested)
            {
                var peerTcpClient = await peer_listener.AcceptTcpClientAsync(cancellationToken);
                using (Logger.BeginScope("New Peer {RemoteEndPoint}", peerTcpClient.Client?.RemoteEndPoint))
                {
                    Logger.LogDebug("New peer connection from {RemoteEndPoint}", peerTcpClient.Client?.RemoteEndPoint);
                    var peer = Peer.CreatePeerFromAccept(peerTcpClient, Logger);
                    _ = Peers.TryAdd(peer.RemoteEndPoint!, peer);
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(async () =>
                    {
                        var shutdown = !await peer.HandleSyn(context, cancellationToken);
                        if (shutdown)
                            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                        else if (peer.IdentityPublicKeyThumbprint == null
                            || peer.IdentityPublicKey == null)
                        {
                            Logger.LogError("Identity public key malformed or not initialized after Syn handled.");
                            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                        }
                        else
                            ThumbprintSignatureCache.TryAdd(DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint), peer.IdentityPublicKey.Value);

                    }, cancellationToken));
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Exception in peer listener loop");
            throw;
        }
    }
    private void PeerJanitorTask(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Thread.Sleep(60000); // Janitor runs once per minute.

                var activeConnections = IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections();

                foreach (var peer in Peers.Values)
                {
                    var peer_tcp_info = activeConnections
                            .SingleOrDefault(x => x.LocalEndPoint.Equals(peer.LocalEndPoint)
                                                && x.RemoteEndPoint.Equals(peer.RemoteEndPoint)
                            );
                    var peer_state = peer_tcp_info != null ? peer_tcp_info.State : TcpState.Unknown;
                    if (peer_state != TcpState.Established || !peer.IsWriteable)
                        Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Exception in peer janitor loop");
            throw;
        }
    }
    private async Task PeerDialerTask(NodeContext context, CancellationToken cancellationToken)
    {
        while (Phonebook == null || Phonebook.Length == 0)
        {
            // Sleep for one hour.
            Logger.LogDebug("No entries in the phone book; dialer sleeping for one hour.");
            Thread.Sleep(60 * 60000);
        }

        try
        {
            Thread.Sleep(5000); // Dialer starts after 5 seconds.
            do
            {
                foreach (var endpoint in Phonebook)
                {
                    var peer = await Peer.CreatePeerAndConnect(endpoint, Logger, cancellationToken);
                    if (peer == null)
                        continue;
                    var added = Peers.TryAdd(peer.RemoteEndPoint!, peer);
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => SendSyn(context, peer, cancellationToken), cancellationToken));
                }

                foreach (var peer in Peers.Values)
                {
                    var peer_tcp_info = IPGlobalProperties.GetIPGlobalProperties()
                            .GetActiveTcpConnections()
                            .SingleOrDefault(x => x.LocalEndPoint.Equals(peer.LocalEndPoint)
                                                && x.RemoteEndPoint.Equals(peer.RemoteEndPoint)
                            );
                    var peer_state = peer_tcp_info != null ? peer_tcp_info.State : TcpState.Unknown;
                    if (peer_state != TcpState.Established || !peer.IsWriteable)
                        Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
                Thread.Sleep(5 * 60000); // Dialer then runs every 5 minutes.
            } while (!cancellationToken.IsCancellationRequested);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Exception in dialer loop");
            throw;
        }
    }

    private async Task PeerHandleInputTask(NodeContext context, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (Thread.Yield())
                Thread.Sleep(200);

            // Peer walk
            foreach (var peer in Peers.Values)
            {
                var shutdown = !await peer.HandleInputAsync(context, ThumbprintSignatureCache, cancellationToken);
                if (shutdown)
                {
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                    continue;
                }
            }
        }
    }

    #endregion

    private async Task SendSyn(NodeContext context, Peer peer, CancellationToken cancellationToken)
    {
        if (peer.IsWriteable)
        {
            Logger.LogDebug("Sending Syn to peer {LocalEndPoint}->{RemoteEndPoint}", peer.LocalEndPoint, peer.RemoteEndPoint);
            await peer.SendSyn(context, cancellationToken);

            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(async () =>
            {
                var shutdown = !await peer.HandleAck(context, cancellationToken);
                if (shutdown)
                {
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
                else if (peer.IdentityPublicKeyThumbprint == null
                    || peer.IdentityPublicKey == null)
                {
                    Logger.LogError("Identity public key malformed or not initialized after Ack handled.");
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
                else
                {
                    ThumbprintSignatureCache.TryAdd(DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint), peer.IdentityPublicKey.Value);

                    // Okay, we made it!
                    Logger.LogDebug("Sending test message to peer {PeerShortName} ({RemoteEndPoint}) thumbprint {Thumbprint}", peer.ShortName, peer.RemoteEndPoint, DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint!));

                    var payload = new ConsoleAlert
                    {
                        Message = "WE DID IT!"
                    };
                    try
                    {
                        var directed = PrepareDirectedMessage(peer.IdentityPublicKeyThumbprint.Value, payload);
                        var envelope = peer.PrepareEnvelope(directed, context.Logger);
                        await peer.SendEnvelope(envelope, Logger, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(ex, "Failed to send sample message; closing down connection to victim {PeerShortName} ({RemoteEndPoint}).", peer.ShortName, peer.RemoteEndPoint);
                        peer.CloseInternal();
                        Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                    }
                }

            }, cancellationToken));
        }
    }

    private async Task HandleUserInput(NodeContext context, string input, CancellationToken cancellationToken)
    {
        input = input.Trim(' ', '\r', '\n');
        if (input.Length == 0)
            return;

        //Logger.LogTrace($"USER INPUT: '{input}'");
        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                await context.WriteLineToUserAsync("\r\nCommand List", cancellationToken);
                var built_in_cmds = new string[] { "cache", "close", "connect", "node", "peers", "shutdown" };
                var cmd_string = built_in_cmds
                    .Union(ConsoleCommands.Select(cc => cc.Command.ToLowerInvariant()).ToArray())
                    .Order()
                    .Aggregate((c, n) => $"{c}\r\n{n}");
                await context.WriteLineToUserAsync(cmd_string, cancellationToken);
                await context.WriteLineToUserAsync("End of Command List", cancellationToken);
                break;

            case "cache":
                {
                    await context.WriteLineToUserAsync("\r\nThumbprint Cache List", cancellationToken);
                    var thumb_len = ThumbprintSignatureCache.IsEmpty ? 0 : ThumbprintSignatureCache.Keys.Max(p => p.Length);
                    await context.WriteLineToUserAsync($"{"IdPubKeyThumbprint".PadRight(thumb_len)} IdPubKey", cancellationToken);

                    foreach (var cache in ThumbprintSignatureCache)
                    {
                        await context.WriteLineToUserAsync($"{cache.Key} {DisplayUtils.BytesToHex(cache.Value)}", cancellationToken);
                    }
                    await context.WriteLineToUserAsync("End of Thumbprint Cache List", cancellationToken);
                    break;
                }

            case "close":
                {
                    if (words.Length != 2)
                    {
                        await context.WriteLineToUserAsync($"CLOSE command requires one argument, the peer short name to close.", cancellationToken);
                        return;
                    }

                    var peer_to_close = Peers.Values.FirstOrDefault(p => string.Compare(p.ShortName, words[1], StringComparison.OrdinalIgnoreCase) == 0);
                    if (peer_to_close == null)
                    {
                        await context.WriteLineToUserAsync($"No peer found with name '{words[1]}'.", cancellationToken);
                        return;
                    }

                    ShutdownPeer(peer_to_close);
                    await context.WriteLineToUserAsync($"Closed connection to peer {peer_to_close.ShortName}.", cancellationToken);
                    break;
                }

            case "connect":
                {
                    if (words.Length != 2)
                    {
                        await context.WriteLineToUserAsync($"CONNECT command requires one argument, the remote endpoint in the format ADDRESS:PORT", cancellationToken);
                        return;
                    }

                    if (!IPEndPoint.TryParse(words[1], out IPEndPoint? remoteEndpoint))
                    {
                        await context.WriteLineToUserAsync($"Cannot parse '' as an IP endpoint in the format ADDRESS:PORT.  Did you provide an IPv6 address and forget to put it brackets?", cancellationToken);
                        return;
                    }

                    var peer = await Peer.CreatePeerAndConnect(remoteEndpoint, Logger, cancellationToken);
                    if (peer == null)
                        return;

                    var added = Peers.TryAdd(peer.RemoteEndPoint!, peer);
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => SendSyn(context, peer, cancellationToken), cancellationToken));
                    await context.WriteLineToUserAsync($"New peer created.", cancellationToken);
                    break;
                }

            case "node":
                await context.WriteLineToUserAsync($"ID Public Key: {DisplayUtils.BytesToHex(IdentityKeyPublicThumbprint)}", cancellationToken);
                return;

            case "peers":
                await context.WriteLineToUserAsync("\r\nPeer List", cancellationToken);
                var state_len = Peers.IsEmpty ? 0 : Peers.Values.Max(p => p.State.ToString().Length);
                var rep_len = Peers.IsEmpty ? 0 : Peers.Values.Max(p => p.RemoteEndPoint == null ? 0 : p.RemoteEndPoint.ToString()!.Length);
                await context.WriteLineToUserAsync($"PeerShortName {"State".PadRight(state_len)} {"RemoteEndPoint".PadRight(rep_len)} Recv Sent IdPubKeyThumbprint", cancellationToken);
                foreach (var peer in Peers.Values)
                {
                    await context.WriteLineToUserAsync($"{peer.ShortName.PadRight("PeerShortName".Length)} {peer.State.ToString().PadRight(state_len)} {(peer.RemoteEndPoint == null ? string.Empty.PadRight("RemoteEndPoint".Length) : peer.RemoteEndPoint.ToString()!).PadRight(rep_len)} {peer.BytesReceived.ToString().PadRight("Recv".Length)} {peer.BytesSent.ToString().PadRight("Sent".Length)} {DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint)}", cancellationToken);
                }
                await context.WriteLineToUserAsync("End of Peer List", cancellationToken);
                break;

            case "shutdown":
                Environment.Exit(0);
                break;

            default:
                var appCommand = ConsoleCommands.FirstOrDefault(cc => string.Compare(cc.Command, command, StringComparison.InvariantCultureIgnoreCase) == 0);
                if (appCommand == null)
                {
                    await context.WriteLineToUserAsync($"Huh?", cancellationToken);
                    return;
                }

                var success = await appCommand.Invoke(words, cancellationToken);
                break;
        }
    }

    private void ShutdownPeer(Peer peer)
    {
        ArgumentNullException.ThrowIfNull(peer);

        var remoteEndPoint = peer.RemoteEndPoint; // Save before CloseInternal clears this.
        peer.CloseInternal();

        if (remoteEndPoint != null && Peers.TryRemove(new KeyValuePair<EndPoint, Peer>(remoteEndPoint, peer)))
            Logger.LogDebug("Removed dead peer {PeerShortName} RemoteEndPoint {RemoteEndPoint}", peer.ShortName, remoteEndPoint);
        else
            Logger.LogError("Dead peer {PeerShortName} RemoteEndPoint {RemoteEndPoint}!", peer.ShortName, remoteEndPoint);
    }

    internal IMessage? PrepareEnvelopePayload(
        ImmutableArray<byte>? routingPeerThumbprint,
        ImmutableArray<byte> ultimateDestinationThumbprint,
        IMessage innerPayload)
    {
        ArgumentNullException.ThrowIfNull(ultimateDestinationThumbprint);
        ArgumentNullException.ThrowIfNull(innerPayload);

        if (routingPeerThumbprint != null && routingPeerThumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(routingPeerThumbprint), $"Thumbprints must be {Constants.THUMBPRINT_LEN} bytes, but the one provided was {routingPeerThumbprint.Value.Length} bytes");
        if (ultimateDestinationThumbprint.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(ultimateDestinationThumbprint), $"Thumbprints must be {Constants.THUMBPRINT_LEN} bytes, but the one provided was {ultimateDestinationThumbprint.Length} bytes");

        // Can I send this to a neighboring peer? (the answer is always no if routing != ultimate for source routed outbound)
        var direct_peer = (routingPeerThumbprint != null && !Enumerable.SequenceEqual(routingPeerThumbprint, ultimateDestinationThumbprint))
            ? null
            : Peers.Values
                .FirstOrDefault(p => p.IdentityPublicKeyThumbprint.HasValue
                && Enumerable.SequenceEqual(p.IdentityPublicKeyThumbprint.Value, ultimateDestinationThumbprint));
        if (direct_peer != null)
        {
            // DM
            return PrepareDirectedMessage(direct_peer.IdentityPublicKeyThumbprint.Value, innerPayload);
        }
        else
        {
            // FWD
            byte[] forwardIdBytes = new byte[8];
            RandomNumberGenerator.Fill(forwardIdBytes);
            var forwardId = BitConverter.ToUInt64(forwardIdBytes);
            if (ForwardIds.TryAdd(forwardId, false))
            {
                var nodeIdPrivateKey = (DilithiumPrivateKeyParameters)IdentityKeys.Private;
                var nodeSigner = new DilithiumSigner();
                nodeSigner.Init(true, nodeIdPrivateKey);
                var packed_payload = Any.Pack(innerPayload);
                var signature = nodeSigner.GenerateSignature(packed_payload.ToByteArray());

                return new ForwardedMessage
                {
                    ForwardId = forwardId,
                    Ttl = 20,
                    SrcIdentityThumbprint = ByteString.CopyFrom([.. IdentityKeyPublicThumbprint]),
                    DstIdentityThumbprint = ByteString.CopyFrom([.. ultimateDestinationThumbprint]),
                    Payload = packed_payload,
                    Signature = ByteString.CopyFrom(signature)
                };
            }
        }

        return null;
    }

    private DirectedMessage PrepareDirectedMessage(ImmutableArray<byte> destinationIdPubKeyThumbprint, IMessage payload)
    {
        ArgumentNullException.ThrowIfNull(destinationIdPubKeyThumbprint);
        ArgumentNullException.ThrowIfNull(payload);

        if (destinationIdPubKeyThumbprint.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(destinationIdPubKeyThumbprint), $"Thumbprint should be {Constants.THUMBPRINT_LEN} bytes long but was {destinationIdPubKeyThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        if (Enumerable.SequenceEqual(destinationIdPubKeyThumbprint, IdentityKeyPublicThumbprint))
            throw new ArgumentException("Attempted to prepare direct messages to my own node", nameof(destinationIdPubKeyThumbprint));

        var nodeIdPrivateKey = (DilithiumPrivateKeyParameters)IdentityKeys.Private;
        var nodeSigner = new DilithiumSigner();
        nodeSigner.Init(true, nodeIdPrivateKey);
        var packed_payload = Any.Pack(payload);
        var signature = nodeSigner.GenerateSignature(packed_payload.ToByteArray());

        var dm = new DirectedMessage
        {
            // The source is my own node.
            SrcIdentityThumbprint = ByteString.CopyFrom([.. IdentityKeyPublicThumbprint]),
            // The desitnation is some other node I know by its thumbprint.
            DstIdentityThumbprint = ByteString.CopyFrom([.. destinationIdPubKeyThumbprint]),
            Payload = packed_payload,
            Signature = ByteString.CopyFrom(signature),
        };

        return dm;
    }

    public IEnumerable<ImmutableArray<byte>> GetNeighborThumbprints() =>
        Peers.Where(p => p.Value.IdentityPublicKeyThumbprint != null)
            .Select(p => p.Value.IdentityPublicKeyThumbprint!.Value);

    public bool RegisterForwardId(UInt64 forwardId)
    {
        var known = ForwardIds.TryGetValue(forwardId, out bool seenBefore);
        if (!known)
            ForwardIds.TryAdd(forwardId, true);
        else if (!seenBefore)
            ForwardIds.TryUpdate(forwardId, true, seenBefore);
        return known && seenBefore;
    }

    public ImmutableArray<byte>? FindPeerThumbprintByShortName(string shortName)
    {
        var peer = Peers.Values.FirstOrDefault(p => string.Compare(p.ShortName, shortName, StringComparison.OrdinalIgnoreCase) == 0);
        return peer?.IdentityPublicKeyThumbprint;
    }

    internal Peer? FindPeerByThumbprint(ImmutableArray<byte> thumbprint) =>
        Peers.Values
            .FirstOrDefault(p => p.IdentityPublicKeyThumbprint != null && Enumerable.SequenceEqual(p.IdentityPublicKeyThumbprint, thumbprint));


    internal async Task InitiateForwardMessage(ForwardedMessage original, ILogger? logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(logger);

        foreach (var peer in Peers.Values)
        {
            var envelope = peer.PrepareEnvelope(original, logger);
            await peer.SendEnvelope(envelope, logger, cancellationToken);
            Logger?.LogDebug("FORWARD to {PeerShortName} ({RemoteEndPoint}) intended for {DestinationThumbprint}: ForwardId={ForwardId}", peer.ShortName, peer.RemoteEndPoint, DisplayUtils.BytesToHex(original.DstIdentityThumbprint), original.ForwardId);
        }
    }

    internal void AdvisePeerPathToIdentity(Peer peer, ImmutableArray<byte>? thumbprint)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(thumbprint);

        if (thumbprint != null && thumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(thumbprint), $"Thumbprint should be {Constants.THUMBPRINT_LEN} bytes long but was {thumbprint.Value.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        // This cache is keyed by string representations of thumbprints.
        // The cache value is the peer short name
        var cacheKey = DisplayUtils.BytesToHex(thumbprint);

        ThumbprintPeerPaths.Set(cacheKey, peer.ShortName, new MemoryCacheEntryOptions
        {
            SlidingExpiration = new TimeSpan(0, 15, 0) // For 15 minutes
        });
    }

    internal async Task RelayForwardMessage(ForwardedMessage original, ImmutableArray<byte>? excludedNeighborThumbprint, ILogger? logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(logger);

        if (excludedNeighborThumbprint != null && excludedNeighborThumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(excludedNeighborThumbprint), $"Thumbprints must be {Constants.THUMBPRINT_LEN} bytes, but the one provided was {excludedNeighborThumbprint.Value.Length} bytes");

        var relayed = new ForwardedMessage
        {
            ForwardId = original.ForwardId,
            Ttl = original.Ttl - 1,
            SrcIdentityThumbprint = original.SrcIdentityThumbprint,
            DstIdentityThumbprint = original.DstIdentityThumbprint,
            Payload = original.Payload,
            Signature = original.Signature,
        };

        foreach (var peer in Peers.Values)
        {
            if (excludedNeighborThumbprint != null
                && peer.IdentityPublicKeyThumbprint != null
                && Enumerable.SequenceEqual(peer.IdentityPublicKeyThumbprint.Value, excludedNeighborThumbprint.Value))
                continue;
            var envelope = peer.PrepareEnvelope(relayed, logger);
            await peer.SendEnvelope(envelope, logger, cancellationToken);
            Logger?.LogDebug("FORWARD to {PeerShortName} ({RemoteEndPoint}) intended for {DestinationThumbprint}: ForwardId={ForwardId}", peer.ShortName, peer.RemoteEndPoint, DisplayUtils.BytesToHex(relayed.DstIdentityThumbprint), relayed.ForwardId);
        }
    }

    public async Task<(bool handled, bool success)> TryHandleMessage(IRequestContext requestContext, Any message, CancellationToken cancellationToken)
    {
        foreach (var serverApp in ServerApps)
        {
            if (serverApp.CanHandle(message))
            {
                var success = await serverApp.HandleMessage(requestContext, message, cancellationToken);
                return (true, success);
            }
        }

        return (false, false);
    }


    internal async Task WriteLineToUserAsync(string message, CancellationToken cancellationToken)
    {
        if (User == null)
            return;
        if (!User.Connected)
            return;
        var stream = User.GetStream();
        if (stream == null)
            return;
        if (!stream.CanWrite)
            return;

        var bytes_to_write = Encoding.UTF8.GetBytes($"{message}\r\n");
        try
        {
            await stream.WriteAsync(bytes_to_write, cancellationToken);
        }
        catch (Exception ex)
        {
            // Swallow.
            Logger?.LogError(ex, "Unable to write message to user. Closing.");
            User.Close();
        }
    }

    [GeneratedRegex("(?:^|\\s)(\\\"(?:[^\\\"])*\\\"|[^\\s]*)")]
    private static partial Regex QuotedWordArrayRegex();
}