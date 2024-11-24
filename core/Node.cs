using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Config;
using Luxelot.Messages;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using static Luxelot.Apps.Common.RegexUtils;

namespace Luxelot;

public class Node
{
    public const uint NODE_PROTOCOL_VERSION = 1;

    private readonly ILogger? Logger;
    public required IPAddress ListenAddress { get; init; } = IPAddress.Any;
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
    //private readonly AsymmetricCipherKeyPair IdentityKeys;
    public readonly ImmutableArray<byte> IdentityKeyPublicBytes;
    public readonly ImmutableArray<byte> IdentityKeyPublicThumbprint;
    private readonly ImmutableArray<byte> IdentityKeyPrivateBytes;
    public string Name { get; init; }
    public string ShortName { get; init; }

    // Plug-ins
    private readonly List<IServerApp> ServerApps = [];
    private readonly List<IClientApp> ClientApps = [];
    private IClientApp? ActiveClientApp = null;


    private Node(ILoggerFactory loggerFactory, AsymmetricCipherKeyPair acp)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        ArgumentNullException.ThrowIfNull(acp);

        var identityKeysPublicBytes = ((DilithiumPublicKeyParameters)acp.Public).GetEncoded();
        IdentityKeyPublicBytes = [.. identityKeysPublicBytes];
        IdentityKeyPublicThumbprint = [.. SHA256.HashData(identityKeysPublicBytes)];
        IdentityKeyPrivateBytes = [.. ((DilithiumPrivateKeyParameters)acp.Private).GetEncoded()];
        Name = DisplayUtils.BytesToHex(IdentityKeyPublicThumbprint);
        ShortName = $"{Name[..8]}...";
        Logger = loggerFactory.CreateLogger($"Node {ShortName}");

        Logger.LogInformation("Recreated node with identity key thumbprint {Thumbprint}", Name);

        ThumbprintPeerPaths = new(new MemoryCacheOptions { }, loggerFactory);
        Logger.LogInformation("Setup memory caches");
    }

    public Node(IHost host, string? shortName)
    {
        ArgumentNullException.ThrowIfNull(host);

        var loggerFactory = (ILoggerFactory?)host.Services.GetService(typeof(ILoggerFactory));

        var acp = CryptoUtils.GenerateDilithiumKeyPair();
        var identityKeysPublicBytes = ((DilithiumPublicKeyParameters)acp.Public).GetEncoded();
        IdentityKeyPublicBytes = [.. identityKeysPublicBytes];
        IdentityKeyPublicThumbprint = [.. SHA256.HashData(identityKeysPublicBytes)];
        IdentityKeyPrivateBytes = [.. ((DilithiumPrivateKeyParameters)acp.Private).GetEncoded()];
        Name = DisplayUtils.BytesToHex(IdentityKeyPublicThumbprint);
        if (string.IsNullOrWhiteSpace(shortName))
        {
            ShortName = $"{Name[..8]}...";
            Logger = loggerFactory?.CreateLogger($"Node {ShortName}");
        }
        else
        {
            ShortName = shortName;
            Logger = loggerFactory?.CreateLogger($"Node {shortName}({Name[..8]}...)");
        }

        Logger?.LogInformation("Generated node identity key with thumbprint {Thumbprint}", Name);

        ThumbprintPeerPaths = loggerFactory == null
            ? new(new MemoryCacheOptions { })
            : new(new MemoryCacheOptions { }, loggerFactory);
        Logger?.LogInformation("Setup memory caches");
    }

    internal static Node? CreateFromEncryptedKeyContainer(
        ILogger logger,
        ILoggerFactory nodeLoggerFactory,
        byte[] encryptedKeyContainer,
        string salt62,
        string? password,
        IPAddress listenAddress,
        ushort peerPort,
        ushort userPort,
        IPEndPoint[]? phonebook)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(nodeLoggerFactory);
        ArgumentNullException.ThrowIfNull(encryptedKeyContainer);
        ArgumentNullException.ThrowIfNull(salt62);

        string json;
        if (password == null)
        {
            json = Encoding.UTF8.GetString(encryptedKeyContainer);
        }
        else
        {
            var passphrase_bytes = Encoding.UTF8.GetBytes(password);
            var salt = salt62.ConvertFromBase62();
            if (salt.Length != 16)
                throw new ArgumentException("Salt must be 16 bytes", nameof(salt62));

            var aes = Aes.Create();
            var pbk = SCrypt.Generate(passphrase_bytes, salt, 1048576, 8, 1, aes.KeySize / 8);
            aes.Key = pbk;
            byte[] jsonBytes;
            try
            {
                jsonBytes = aes.DecryptCbc(encryptedKeyContainer, salt, PaddingMode.PKCS7);
            }
            catch (CryptographicException ce)
            {
                logger.LogError(ce, "Node creation failed; unable to decrypt key container.");
                return null;
            }

            json = Encoding.UTF8.GetString(jsonBytes);
        }

        var kc = System.Text.Json.JsonSerializer.Deserialize<KeyContainer>(json) ?? throw new InvalidOperationException("Unable to deserialize key container");

        var pub = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, Convert.FromBase64String(kc.PublicKeyBase64));
        var pri = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium5, Convert.FromBase64String(kc.PrivateKeyBase64), pub);

        var identityKeys = new AsymmetricCipherKeyPair(pub, pri);

        return new Node(nodeLoggerFactory, identityKeys)
        {
            ListenAddress = listenAddress,
            PeerPort = peerPort,
            UserPort = userPort,
            Phonebook = phonebook,
        };
    }

    public async void Main(IHost host, CancellationToken cancellationToken)
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
        if (assemblyPath == null)
        {
            Logger?.LogWarning("Unable to determine assembly path.  Skipping plugin loads.");
        }
        else
        {
            Logger?.LogInformation("Looking for plugins to load in {AssemblyPath}", assemblyPath);
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
                            LoadApp(host, potentialPlugin);
                        }
                    }
                    catch (BadImageFormatException)
                    {
                        // Swallow.
                    }
                }
            }
        }

        Logger?.LogTrace("Setting up loopback peer");
        {
            var loopbackEndpoint = new IPEndPoint(IPAddress.IPv6Loopback, IPEndPoint.MaxPort);
            Peers.TryAdd(loopbackEndpoint, new Peer(Logger));
        }

        Logger?.LogTrace("Setting up user listener loop");
        {
            var user_listener_task = Task.Run(async () => await UserListenerTask(nodeContext, cts.Token), cancellationToken);
            var user_listener_task_entry = new TaskEntry { Name = "User listener loop", EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(user_listener_task_entry, user_listener_task);
            Logger?.LogTrace("User listener loop is a persistent background worker task {TaskId}", user_listener_task_entry.TaskId);
        }

        Logger?.LogTrace("Setting up peer listener loop");
        {
            var peer_listener_task = Task.Run(async () => await PeerListenerTask(nodeContext, cts.Token), cancellationToken);
            var peer_listener_task_entry = new TaskEntry { Name = "Peer listener loop", EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_listener_task_entry, peer_listener_task);
            Logger?.LogTrace("Peer listener loop is a persistent background worker task {TaskId}", peer_listener_task_entry.TaskId);
        }

        Logger?.LogTrace("Setting up peer janitor loop");
        {
            var peer_janitor_task = Task.Run(() => PeerJanitorTask(cts.Token), cancellationToken);
            var peer_janitor_task_entry = new TaskEntry { Name = "Peer janitor loop", EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_janitor_task_entry, peer_janitor_task);
            Logger?.LogTrace("Peer janitor loop is a persistent background worker task {TaskId}", peer_janitor_task_entry.TaskId);
        }

        Logger?.LogTrace("Setting up peer dialer loop");
        {
            var peer_dialer_task = Task.Run(() => PeerDialerTask(nodeContext, cts.Token), cancellationToken);
            var dialer_task_entry = new TaskEntry { Name = "Peer dialer", EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(dialer_task_entry, peer_dialer_task);
            Logger?.LogTrace("Dialer loop is a persistent background worker task {TaskId}", dialer_task_entry.TaskId);
        }

        Logger?.LogTrace("Setting up peer connected input handler loop");
        {
            var peer_handler_task = Task.Run(() => PeerHandleInputTask(nodeContext, cts.Token), cancellationToken);
            var peer_handler_task_entry = new TaskEntry { Name = "Peer connected input handler", EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_handler_task_entry, peer_handler_task);
            Logger?.LogTrace("Peer input handler loop is a persistent background worker task {TaskId}", peer_handler_task_entry.TaskId);
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
                                Logger?.LogError("Persistent background worker is not alive task {TaskId}", t.Key.TaskId);
                                throw new InvalidOperationException($"Persistent background worker is not alive task {t.Key.TaskId}");
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
                                Logger?.LogTrace("Removed completed task {TaskId} ({TaskName})", t.Key.TaskId, t.Key.Name);
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

    public void LoadApp(IHost host, string appPath)
    {
        ArgumentNullException.ThrowIfNull(appPath);

        var appContext = new AppContext()
        {
            Logger = Logger,
            Node = this,
        };

        // Load Apps
        var config = (IConfiguration?)host.Services.GetService(typeof(IConfiguration));
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
                    Logger?.LogError("Unable to load server app {TypeName}", serverAppType.FullName);
                    continue;
                }

                var appConfig = config?.GetSection("Apps").GetSection(serverApp.Name);

                serverApp.OnNodeInitialize(appContext, appConfig);
                ServerApps.Add(serverApp);
                Logger?.LogInformation("Loaded server app {AppName} ({TypeName})", serverApp.Name, serverAppType.FullName);
            }

            // Load Client Apps
            var clientAppTypes = types.Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IClientApp).FullName) == 0)).ToArray();
            foreach (var clientAppType in clientAppTypes)
            {
                var objApp = Activator.CreateInstance(clientAppType, true);
#pragma warning disable IDE0019 // Use pattern matching
                var clientApp = objApp as IClientApp;
#pragma warning restore IDE0019 // Use pattern matching
                if (clientApp == null)
                {
                    Logger?.LogError("Unable to load client app {TypeName}", clientAppType.FullName);
                    continue;
                }

                clientApp.OnInitialize(appContext);
                ClientApps.Add(clientApp);
                Logger?.LogInformation("Loaded client app {AppName} ({TypeName})", clientApp.Name, clientAppType.FullName);
            }
        }
    }

    #region Tasks
    private async Task UserListenerTask(NodeContext context, CancellationToken cancellationToken)
    {
        try
        {
            using TcpListener user_listener = new(IPAddress.Loopback, UserPort);
            user_listener.Start();
            Logger?.LogInformation("Listening for local user commands at {LocalEndpoint}", user_listener.LocalEndpoint);
            while (!cancellationToken.IsCancellationRequested)
            {
                var user = await user_listener.AcceptTcpClientAsync(cancellationToken);
                using (Logger?.BeginScope($"User Connection {user.Client?.RemoteEndPoint}"))
                {
                    Logger?.LogDebug("New user connection from {RemoteEndPoint}", user.Client?.RemoteEndPoint);

                    var okay = UserMutex.WaitOne(5000); // Wait at most 5 seconds
                    if (!okay)
                    {
                        Logger?.LogError("Unable to obtain mutex to accept user connection.");
                        continue;
                    }

                    try
                    {
                        if (User != null)
                        {
                            Logger?.LogWarning($"A user connection already exists from {User.Client?.RemoteEndPoint}. Shutting that one down to use this new one from {user.Client?.RemoteEndPoint}");
                            try
                            {
                                await User.GetStream().WriteAsync(Encoding.UTF8.GetBytes($"\r\nUSER CONNECTING FROM {user.Client?.RemoteEndPoint}\r\nGOODBYE.\r\n"), cancellationToken);
                            }
                            catch (Exception ex)
                            {
                                // Swallow exception..
                                Logger?.LogTrace(ex, "Unable to send goodbye to replaced user connection");
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
                            Logger?.LogInformation("User disconnected from console {RemoteEndPoint}. Closing.", User.Client?.RemoteEndPoint);
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
            Logger?.LogError(ex, "Exception in peer listener loop");
            throw;
        }
    }
    private async Task PeerListenerTask(NodeContext context, CancellationToken cancellationToken)
    {
        try
        {
            using TcpListener peer_listener = new(ListenAddress, PeerPort);
            peer_listener.Start();
            Logger?.LogInformation("Listening for peers at {LocalEndpoint}", peer_listener.LocalEndpoint);
            while (!cancellationToken.IsCancellationRequested)
            {
                var peerTcpClient = await peer_listener.AcceptTcpClientAsync(cancellationToken);
                using (Logger?.BeginScope("New Peer {RemoteEndPoint}", peerTcpClient.Client?.RemoteEndPoint))
                {
                    Logger?.LogDebug("New peer connection from {RemoteEndPoint}", peerTcpClient.Client?.RemoteEndPoint);
                    var peer = Peer.CreatePeerFromAccept(peerTcpClient);
                    _ = Peers.TryAdd(peer.RemoteEndPoint!, peer);
                    Tasks.TryAdd(new TaskEntry { Name = $"Accept connection from {peerTcpClient.Client?.RemoteEndPoint?.ToString() ?? "new peer"}", EventType = TaskEventType.FireOnce }, Task.Run(async () =>
                    {
                        var shutdown = !await peer.HandleSyn(context, cancellationToken);
                        if (shutdown)
                            Tasks.TryAdd(new TaskEntry { Name = $"Shutdown after Syn from {peerTcpClient.Client?.RemoteEndPoint?.ToString() ?? "new peer"}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                        else if (peer.IdentityPublicKeyThumbprint == null
                            || peer.IdentityPublicKey == null)
                        {
                            Logger?.LogError("Identity public key malformed or not initialized after Syn handled.");
                            Tasks.TryAdd(new TaskEntry { Name = $"Shutdown after malfored key on Syn from {peerTcpClient.Client?.RemoteEndPoint?.ToString() ?? "new peer"}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                        }
                        else
                            ThumbprintSignatureCache.TryAdd(DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint), peer.IdentityPublicKey.Value);

                    }, cancellationToken));
                }
            }
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "Exception in peer listener loop");
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

                foreach (var peer in Peers.Values.Where(p => !p.IsLoopback))
                {
                    var peer_tcp_info = activeConnections
                            .SingleOrDefault(x => x.LocalEndPoint.Equals(peer.LocalEndPoint)
                                                && x.RemoteEndPoint.Equals(peer.RemoteEndPoint)
                            );
                    var peer_state = peer_tcp_info != null ? peer_tcp_info.State : TcpState.Unknown;
                    if (peer_state != TcpState.Established || !peer.IsWriteable)
                        Tasks.TryAdd(new TaskEntry { Name = $"Shutdown dead peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
            }
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "Exception in peer janitor loop");
            throw;
        }
    }

    private async Task PeerDialerTask(NodeContext context, CancellationToken cancellationToken)
    {
        try
        {
            Thread.Sleep(3000); // Dialer starts after 3 seconds.
            while (!cancellationToken.IsCancellationRequested)
            {
                var pb = Phonebook;
                if (pb == null || pb.Length == 0)
                {
                    // Sleep for one hour.
                    Logger?.LogDebug("No entries in the phone book; dialer sleeping for one hour.");
                    Thread.Sleep(60 * 60000);
                    continue;
                }

                foreach (var endpoint in pb)
                {
                    var peer = await Peer.CreatePeerAndConnect(endpoint, Logger, cancellationToken);
                    if (peer == null)
                        continue;
                    var added = Peers.TryAdd(peer.RemoteEndPoint!, peer);
                    Tasks.TryAdd(new TaskEntry { Name = $"Dialing out to peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => SendSyn(context, peer, cancellationToken), cancellationToken));
                }

                Thread.Sleep(10 * 60000); // Wait 10 seconds before queuing dead peer tasks.

                foreach (var peer in Peers.Values.Where(p => !p.IsLoopback))
                {
                    var peer_tcp_info = IPGlobalProperties.GetIPGlobalProperties()
                            .GetActiveTcpConnections()
                            .FirstOrDefault(x => x.LocalEndPoint.Equals(peer.LocalEndPoint)
                                                && x.RemoteEndPoint.Equals(peer.RemoteEndPoint)
                            );
                    var peer_state = peer_tcp_info != null ? peer_tcp_info.State : TcpState.Unknown;
                    if (peer_state != TcpState.Established || !peer.IsWriteable)
                        Tasks.TryAdd(new TaskEntry { Name = $"Shutting down dead or non-responsive peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
                Thread.Sleep(5 * 60000); // Dialer then runs every 5 minutes.
            };
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "Exception in dialer loop");
            throw;
        }
    }

    private async Task PeerHandleInputTask(NodeContext context, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Thread.Sleep(100);

            // Peer walk
            await Parallel.ForEachAsync(Peers.Values, cancellationToken, async (peer, c) =>
            {
                var shutdown = !await peer.HandleInputAsync(context, ThumbprintSignatureCache, cancellationToken);
                if (shutdown)
                {
                    Tasks.TryAdd(new TaskEntry { Name = $"Shutting down killed peer {peer.ShortName} ({peer.RemoteEndPoint})", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
            });
        }
    }

    #endregion

    private async Task SendSyn(NodeContext context, Peer peer, CancellationToken cancellationToken)
    {
        if (peer.IsWriteable)
        {
            Logger?.LogDebug("Sending Syn to peer {LocalEndPoint}->{RemoteEndPoint}", peer.LocalEndPoint, peer.RemoteEndPoint);
            await peer.SendSyn(context, cancellationToken);

            Tasks.TryAdd(new TaskEntry { Name = $"Wait for and handle ACK from peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(async () =>
            {
                var shutdown = !await peer.HandleAck(context, cancellationToken);
                if (shutdown)
                {
                    Tasks.TryAdd(new TaskEntry { Name = $"Shutting down at ACK handle for peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
                else if (peer.IdentityPublicKeyThumbprint == null
                    || peer.IdentityPublicKey == null)
                {
                    Logger?.LogError("Identity public key malformed or not initialized after Ack handled.");
                    Tasks.TryAdd(new TaskEntry { Name = $"Shutting down at ACK handle for bad key for peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }
                else
                {
                    ThumbprintSignatureCache.TryAdd(DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint), peer.IdentityPublicKey.Value);

                    // Okay, we made it!
                    Logger?.LogDebug("Sending test message to peer {PeerShortName} ({RemoteEndPoint}) thumbprint {Thumbprint}", peer.ShortName, peer.RemoteEndPoint, DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint!));

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
                        Logger?.LogError(ex, "Failed to send sample message; closing down connection to victim {PeerShortName} ({RemoteEndPoint}).", peer.ShortName, peer.RemoteEndPoint);
                        peer.CloseInternal();
                        Tasks.TryAdd(new TaskEntry { Name = $"Kill unsendable peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
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

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        if (ActiveClientApp != null)
        {
            switch (command.ToLowerInvariant())
            {
                case "exit":
                case "quit":
                    await context.WriteLineToUserAsync($"\r\nExited app {ActiveClientApp.Name}", cancellationToken);
                    ActiveClientApp = null;
                    return;
                default:
                    await ActiveClientApp.HandleUserInput(input, cancellationToken);
                    return;
            }
        }

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("\r\nBuilt-In Command List");
                    var built_in_cmds = new string[] { "cache", "close", "connect", "node", "peers", "shutdown", "version" };
                    sb.AppendLine(built_in_cmds
                        .Order()
                        .Aggregate((c, n) => $"{c}\r\n{n}"));

                    if (ClientApps.Count > 0)
                        sb.AppendLine("\r\nLoaded apps:");
                    foreach (var ca in ClientApps.OrderBy(x => x.InteractiveCommand ?? x.Name))
                    {
                        if (ca.InteractiveCommand != null)
                            sb.AppendLine($"\r\n{ca.InteractiveCommand} - {ca.Name}");
                        else
                            sb.AppendLine($"{ca.Name}");

                        foreach (var com in ca.Commands.OrderBy(x => x.Command))
                            sb.AppendLine($"\t{com.Command}");
                    }
                    sb.AppendLine("\r\nEnd of Command List");
                    await context.WriteLineToUserAsync(sb.ToString(), cancellationToken);
                    break;
                }
            case "version":
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                await context.WriteLineToUserAsync($"Luxelot v{version} running on node {ShortName}", cancellationToken);
                break;

            case "apps":
                {
                    await context.WriteLineToUserAsync("\r\nApps List", cancellationToken);
                    foreach (var app in ServerApps.Order())
                    {
                        await context.WriteLineToUserAsync($"{app.Name}", cancellationToken);
                    }
                    await context.WriteLineToUserAsync("End of Apps List", cancellationToken);

                    break;
                }

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
                    Tasks.TryAdd(new TaskEntry { Name = $"Send SYN to peer {peer.RemoteEndPoint}", EventType = TaskEventType.FireOnce }, Task.Run(() => SendSyn(context, peer, cancellationToken), cancellationToken));
                    await context.WriteLineToUserAsync($"New peer created.", cancellationToken);
                    break;
                }

            case "node":
                await context.WriteLineToUserAsync($"ID Public Key: {DisplayUtils.BytesToHex(IdentityKeyPublicBytes)}", cancellationToken);
                await context.WriteLineToUserAsync($"ID Thumbnail: {DisplayUtils.BytesToHex(IdentityKeyPublicThumbprint)}", cancellationToken);
                return;

            case "peers":
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("\r\nPeer List");
                    var state_len = Peers.IsEmpty ? 0 : Peers.Values.Max(p => p.State.ToString().Length);
                    var rep_len = Peers.IsEmpty ? 0 : Peers.Values.Max(p => p.RemoteEndPoint == null ? 0 : p.RemoteEndPoint.ToString()!.Length);
                    sb.AppendLine($"PeerShortName {"State".PadRight(state_len)} {"RemoteEndPoint".PadRight(rep_len)} Recv Sent IdPubKeyThumbprint");
                    foreach (var peer in Peers.Values)
                    {
                        sb.AppendLine($"{peer.ShortName.PadRight("PeerShortName".Length)} {peer.State.ToString().PadRight(state_len)} {(peer.RemoteEndPoint == null ? string.Empty.PadRight("RemoteEndPoint".Length) : peer.RemoteEndPoint.ToString()!).PadRight(rep_len)} {peer.BytesReceived.ToString().PadRight("Recv".Length)} {peer.BytesSent.ToString().PadRight("Sent".Length)} {DisplayUtils.BytesToHex(peer.IdentityPublicKeyThumbprint)}");
                    }
                    sb.AppendLine("End of Peer List");
                    await context.WriteLineToUserAsync(sb.ToString(), cancellationToken);
                    break;
                }
            case "shutdown":
                Environment.Exit(0);
                break;

            default:
                foreach (var ca in ClientApps)
                {
                    // Maybe it's a client app that has an interactive mode?
                    if (ca.InteractiveCommand != null && string.Compare(ca.InteractiveCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        ActiveClientApp = ca;
                        await ca.OnActivate(cancellationToken);
                        return;
                    }

                    // Or maybe it's a command this client app loaded?
                    var appCommand = ca.Commands.FirstOrDefault(cc => string.Compare(cc.Command, command, StringComparison.InvariantCultureIgnoreCase) == 0);
                    if (appCommand != null)
                    {
                        var success = await appCommand.Invoke(words, cancellationToken);
                        if (!success)
                            await context.WriteLineToUserAsync($"ERROR: {appCommand.Command}", cancellationToken);
                        return;
                    }
                }

                await context.WriteLineToUserAsync($"Huh?", cancellationToken);
                break;
        }
    }

    private void ShutdownPeer(Peer peer)
    {
        ArgumentNullException.ThrowIfNull(peer);

        var remoteEndPoint = peer.RemoteEndPoint; // Save before CloseInternal clears this.
        peer.CloseInternal();

        if (remoteEndPoint != null && Peers.TryRemove(new KeyValuePair<EndPoint, Peer>(remoteEndPoint, peer)))
            Logger?.LogDebug("Removed dead peer {PeerShortName} RemoteEndPoint {RemoteEndPoint}", peer.ShortName, remoteEndPoint);
        else
            Logger?.LogError("Dead peer {PeerShortName} RemoteEndPoint {RemoteEndPoint}!", peer.ShortName, remoteEndPoint);
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
            return PrepareDirectedMessage(direct_peer.IdentityPublicKeyThumbprint!.Value, innerPayload);
        }
        else
        {
            // FWD
            byte[] forwardIdBytes = new byte[8];
            RandomNumberGenerator.Fill(forwardIdBytes);
            var forwardId = BitConverter.ToUInt64(forwardIdBytes);
            if (ForwardIds.TryAdd(forwardId, false))
            {
                var pub = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, [.. IdentityKeyPublicBytes]);
                var pri = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium5, [.. IdentityKeyPrivateBytes], pub);

                var nodeSigner = new DilithiumSigner();
                nodeSigner.Init(true, pri);
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

        var packed_payload = Any.Pack(payload);

        // If destined for loopback, then source is also loopback
        ByteString src;
        byte[] signature;
        if (destinationIdPubKeyThumbprint.All(b => b == 0x00))
        {
            src = ByteString.CopyFrom([.. destinationIdPubKeyThumbprint]);
            signature = []; // No reason to sign loopback messages
        }
        else
        {
            src = ByteString.CopyFrom([.. IdentityKeyPublicThumbprint]);
            var pub = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, [.. IdentityKeyPublicBytes]);
            var pri = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium5, [.. IdentityKeyPrivateBytes], pub);

            var nodeSigner = new DilithiumSigner();
            nodeSigner.Init(true, pri);
            signature = nodeSigner.GenerateSignature(packed_payload.ToByteArray());
        }

        var dm = new DirectedMessage
        {
            // The source is my own node.
            SrcIdentityThumbprint = src,
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

        foreach (var peer in Peers.Values.Where(p => !p.IsLoopback))
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

        foreach (var peer in Peers.Values.Where(p => !p.IsLoopback))
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

    public bool TryAddThumbprintSignatureCache(ImmutableArray<byte> thumbprint, ImmutableArray<byte> publicKey)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);
        ArgumentNullException.ThrowIfNull(publicKey);

        if (thumbprint.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(thumbprint), $"Thumbprint should be {Constants.THUMBPRINT_LEN} bytes long but was {thumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");
        if (publicKey.Length != Constants.KYBER_PUBLIC_KEY_LEN)
            throw new ArgumentOutOfRangeException(nameof(thumbprint), $"Public key should be {Constants.KYBER_PUBLIC_KEY_LEN} bytes long but was {publicKey.Length} bytes.");

        // Don't add loopback
        if (thumbprint.All(b => b == 0x00))
            return false;

        // Verify these match - be paranoid.
        if (!Enumerable.SequenceEqual(thumbprint, SHA256.HashData([.. publicKey])))
            return false;

        return ThumbprintSignatureCache.TryAdd(DisplayUtils.BytesToHex(thumbprint), publicKey);
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

    public (byte[] enc, string salt62) ExportKeyContainer(string? password)
    {
        var kc = new KeyContainer
        {
            PublicKeyBase64 = Convert.ToBase64String([.. IdentityKeyPublicBytes]),
            PrivateKeyBase64 = Convert.ToBase64String([.. IdentityKeyPrivateBytes])
        };

        var json = System.Text.Json.JsonSerializer.Serialize(kc);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        if (password == null)
            return (jsonBytes, "unencrypted");

        var passphrase_bytes = Encoding.UTF8.GetBytes(password);
        var salt = new byte[16];
        if (string.CompareOrdinal(password, "insecure") == 0)
            Array.Copy(passphrase_bytes, salt, passphrase_bytes.Length);
        else
            RandomNumberGenerator.Fill(salt);

        var aes = Aes.Create();
        var pbk = SCrypt.Generate(passphrase_bytes, salt, 1048576, 8, 1, aes.KeySize / 8);
        aes.Key = pbk;
        var encrypted = aes.EncryptCbc(jsonBytes, salt, PaddingMode.PKCS7);
        return (encrypted, salt.ConvertToBase62());
    }
}