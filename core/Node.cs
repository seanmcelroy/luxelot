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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using static Luxelot.Apps.Common.RegexUtils;

namespace Luxelot;

internal class Node : INode
{
    public const uint NODE_PROTOCOL_VERSION = 1;

    public event EventHandler<PeerConnectedArgs>? PeerConnected;

    private readonly ILogger? Logger;
    public required IPAddress ListenAddress { get; init; } = IPAddress.Any;
    public required int PeerPort { get; init; }
    public required int UserPort { get; init; }
    public IPEndPoint[]? Phonebook { get; init; }

    // Local state
    private readonly ConcurrentDictionary<TaskEntry, Task> Tasks = [];
    private readonly ConcurrentDictionary<EndPoint, Peer> Peers = [];

    // Network state
    private readonly ConcurrentDictionary<ulong, bool> ForwardIds = [];
    private readonly MemoryCache ThumbprintPublicKeyCache;
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

    private Node()
    {
        PeerConnected += (sender, args) =>
        {
            var thumbprintHex = Convert.ToHexString(args.Thumbprint.AsSpan());
            ThumbprintPublicKeyCache?.Set(thumbprintHex, args.PublicKey);
        };
    }

    private Node(ILoggerFactory loggerFactory, AsymmetricCipherKeyPair acp) : this()
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        ArgumentNullException.ThrowIfNull(acp);

        var identityKeysPublicBytes = ((MLDsaPublicKeyParameters)acp.Public).GetEncoded();
        IdentityKeyPublicBytes = [.. identityKeysPublicBytes];
        IdentityKeyPublicThumbprint = [.. SHA256.HashData(identityKeysPublicBytes)];
        IdentityKeyPrivateBytes = [.. ((MLDsaPrivateKeyParameters)acp.Private).GetEncoded()];
        Name = Convert.ToHexString(IdentityKeyPublicThumbprint.AsSpan());
        ShortName = $"{Name[..8]}...";
        Logger = loggerFactory.CreateLogger($"Node {ShortName}");
        Logger.LogInformation("Recreated node with identity key thumbprint {Thumbprint}", Name);

        ThumbprintPeerPaths = new(new MemoryCacheOptions { }, loggerFactory);
        ThumbprintPublicKeyCache = new(new MemoryCacheOptions { }, loggerFactory);
        Logger?.LogInformation("Setup memory caches");
    }

    public Node(IHost host, string? shortName) : this()
    {
        ArgumentNullException.ThrowIfNull(host);

        var loggerFactory = (ILoggerFactory?)host.Services.GetService(typeof(ILoggerFactory));

        var acp = CryptoUtils.GenerateDilithiumKeyPair();
        var identityKeysPublicBytes = ((MLDsaPublicKeyParameters)acp.Public).GetEncoded();
        IdentityKeyPublicBytes = [.. identityKeysPublicBytes];
        IdentityKeyPublicThumbprint = [.. SHA256.HashData(identityKeysPublicBytes)];
        IdentityKeyPrivateBytes = [.. ((MLDsaPrivateKeyParameters)acp.Private).GetEncoded()];
        Name = Convert.ToHexString(IdentityKeyPublicThumbprint.AsSpan());
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
        ThumbprintPublicKeyCache = loggerFactory == null
            ? new(new MemoryCacheOptions { })
            : new(new MemoryCacheOptions { }, loggerFactory);
        Logger?.LogInformation("Setup memory caches");
    }

    internal static Node? CreateFromEncryptedKeyContainer(
        ILogger logger,
        ILoggerFactory nodeLoggerFactory,
        ReadOnlySpan<byte> encryptedKeyContainer,
        string salt62,
        string? password,
        IPAddress listenAddress,
        ushort peerPort,
        ushort userPort,
        IPEndPoint[]? phonebook)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(nodeLoggerFactory);
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

        var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, Convert.FromBase64String(kc.PublicKeyBase64));
        var pri = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, Convert.FromBase64String(kc.PrivateKeyBase64));

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
            foreach (var potentialPlugin in Directory.EnumerateFiles(assemblyPath, "*App.dll"))
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
                        case TaskStatus.WaitingForChildrenToComplete:
                        case TaskStatus.WaitingForActivation:
                        case TaskStatus.WaitingToRun:
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
                    case TaskStatus.WaitingForChildrenToComplete:
                    case TaskStatus.WaitingForActivation:
                    case TaskStatus.WaitingToRun:
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
        ArgumentNullException.ThrowIfNull(host);
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
            foreach (var serverAppType in types.Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IServerApp).FullName) == 0)))
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

                serverApp.OnNodeInitialize(this, appContext, appConfig);
                _ = appContext.TryRegisterSingleton(() => serverApp); // Every server gets registered as a singleton in the app context
                ServerApps.Add(serverApp);
                Logger?.LogInformation("Loaded server app {AppName} ({TypeName})", serverApp.Name, serverAppType.FullName);
            }

            // Load Client Apps
            foreach (var clientAppType in types.Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IClientApp).FullName) == 0)))
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
                _ = appContext.TryRegisterSingleton(() => clientApp); // Every client gets registered as a singleton in the app context
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
            try
            {
                user_listener.Start();
            }
            catch (SocketException sx)
            {
                context.Logger?.LogError(sx, "Unable to start user listener on {LocalEndPoint}: Socket error {ErrorCodeName} ({ErrorCode})", user_listener.LocalEndpoint, System.Enum.GetName((SocketError)sx.ErrorCode), sx.ErrorCode);
                throw;
            }

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
                        catch (ObjectDisposedException)
                        {
                            // Swallow exception
                            User = null;
                            continue;
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
            try
            {
                peer_listener.Start();
            }
            catch (SocketException sx)
            {
                context.Logger?.LogError(sx, "Unable to start peer listener on {LocalEndPoint}: {ErrorCodeName} ({ErrorCode})", peer_listener.LocalEndpoint, System.Enum.GetName((SocketError)sx.ErrorCode), sx.ErrorCode);
                throw;
            }

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
                        {
                            Tasks.TryAdd(new TaskEntry { Name = $"Shutdown after Syn from {peerTcpClient.Client?.RemoteEndPoint?.ToString() ?? "new peer"}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                            return;
                        }

                        if (peer.IdentityPublicKeyThumbprint == null
                            || peer.IdentityPublicKey == null)
                        {
                            Logger?.LogError("Identity public key malformed or not initialized after Syn handled.");
                            Tasks.TryAdd(new TaskEntry { Name = $"Shutdown after malfored key on Syn from {peerTcpClient.Client?.RemoteEndPoint?.ToString() ?? "new peer"}", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                            return;
                        }

                        // Notify apps that a peer has connected, in case they care
                        RaisePeerConnected(peer);

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
                        Tasks.TryAdd(new TaskEntry { Name = $"Shutdown dead peer {peer.ShortName} {peer.RemoteEndPoint} (state={System.Enum.GetName(peer_state)})", EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
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
            Thread.Sleep(2000); // Dialer starts after 2 seconds.
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
                var shutdown = !await peer.HandleInputAsync(context, cancellationToken);
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
        if (peer.IsLoopback)
            throw new InvalidOperationException($"Cannot {nameof(SendSyn)} to loopback peer.");

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
                    // Okay, we made it!
                    Logger?.LogDebug("Sending SynAck to peer {PeerShortName} ({RemoteEndPoint}) thumbprint {Thumbprint}", peer.ShortName, peer.RemoteEndPoint, Convert.ToHexString(peer.IdentityPublicKeyThumbprint.Value.AsSpan()));

                    var parts = NetUtils.ConvertIPAddressToMessageIntegers(peer.RemoteEndPoint!.Address)!;
                    var payload = new SynAck
                    {
                        Addr1 = parts[0],
                        Addr2 = parts[1],
                        Addr3 = parts[2],
                        Addr4 = parts[3],
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
        var two_word_command = words.Length == 1 ? null : $"{words[0]} {words[1]}";
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
                    var result = await ActiveClientApp.HandleUserInput(input, cancellationToken);
                    if (result.Success)
                    {
                        if (!string.IsNullOrWhiteSpace(result.ErrorMessage))
                            await context.WriteLineToUserAsync(result.ErrorMessage, cancellationToken);
                        return;
                    }

                    if (string.IsNullOrWhiteSpace(result.ErrorMessage))
                    {
                        if (result.Command != null)
                            await context.WriteLineToUserAsync($"ERROR: {ActiveClientApp.InteractiveCommand} {result.Command.InteractiveCommand}", cancellationToken);
                        else
                            await context.WriteLineToUserAsync($"ERROR", cancellationToken);
                    }
                    else
                    {
                        if (result.Command != null)
                            await context.WriteLineToUserAsync($"ERROR: {ActiveClientApp.InteractiveCommand} {result.Command.InteractiveCommand}: {result.ErrorMessage}", cancellationToken);
                        else
                            await context.WriteLineToUserAsync($"ERROR: {result.ErrorMessage}", cancellationToken);
                    }
                    return;
            }
        }

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                {
                    var sb = new StringBuilder();
                    sb.AppendLine()
                        .AppendLine("COMMAND LIST")
                        .AppendLine("Built-In Commands:");
                    var built_in_cmds = new string[] { "dht", "disconnect", "connect", "node", "peer", "peers", "quit", "shutdown", "version" };
                    sb.AppendLine(built_in_cmds
                        .Order()
                        .Aggregate((c, n) => $"{c}{Environment.NewLine}{n}"));

                    if (ClientApps.Count > 0)
                        sb.AppendLine().AppendLine("Commands from loaded apps:");
                    foreach (var ca in ClientApps.OrderBy(x => x.InteractiveCommand ?? x.Name))
                    {
                        if (ca.InteractiveCommand != null)
                            sb.AppendLine($"\r\n{ca.InteractiveCommand} - {ca.Name}");
                        else
                            sb.AppendLine($"{ca.Name}");

                        var full_len = ca.Commands.Max(com => com.InteractiveCommand.Length);

                        foreach (var com in ca.Commands.OrderBy(x => x.InteractiveCommand))
                            sb.AppendLine($"     {com.InteractiveCommand.PadRight(full_len)}: {com.ShortHelp}");
                    }
                    sb.AppendLine().AppendLine("END OF COMMAND LIST").AppendLine();
                    await context.WriteLineToUserAsync(sb.ToString(), cancellationToken);
                    break;
                }
            case "version":
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                await context.WriteLineToUserAsync($"Luxelot v{version} running on node {ShortName}", cancellationToken);
                break;

            case "apps":
                {
                    await context.WriteLineToUserAsync($"{Environment.NewLine}Apps List", cancellationToken);
                    foreach (var app in ServerApps.Order())
                    {
                        await context.WriteLineToUserAsync($"{app.Name}", cancellationToken);
                    }
                    await context.WriteLineToUserAsync("End of Apps List", cancellationToken);

                    break;
                }

            case "disconnect":
                {
                    if (words.Length != 2)
                    {
                        await context.WriteLineToUserAsync($"Command requires one argument, the peer short name to disconnect.", cancellationToken);
                        return;
                    }

                    var peer_to_disconnect = Peers.Values.FirstOrDefault(p => string.Compare(p.ShortName, words[1], StringComparison.OrdinalIgnoreCase) == 0);
                    if (peer_to_disconnect == null)
                    {
                        await context.WriteLineToUserAsync($"No peer found with name '{words[1]}'.", cancellationToken);
                        return;
                    }

                    ShutdownPeer(peer_to_disconnect);
                    await context.WriteLineToUserAsync($"Disconnected peer {peer_to_disconnect.ShortName}.", cancellationToken);
                    break;
                }

            case "connect":
                {
                    if (words.Length != 2)
                    {
                        await context.WriteLineToUserAsync($"Command requires one argument, the remote endpoint in the format ADDRESS:PORT", cancellationToken);
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
                await context.WriteLineToUserAsync($"ID Public Key: {Convert.ToHexString(IdentityKeyPublicBytes.AsSpan())}", cancellationToken);
                await context.WriteLineToUserAsync($"ID Thumbprint: {Convert.ToHexString(IdentityKeyPublicThumbprint.AsSpan())}", cancellationToken);
                return;

            case "peer":
                {
                    if (words.Length != 2)
                    {
                        await context.WriteLineToUserAsync($"Command requires one argument, the peer short name to examine.", cancellationToken);
                        return;
                    }

                    var peer = Peers.Values.FirstOrDefault(p => string.Compare(p.ShortName, words[1], StringComparison.OrdinalIgnoreCase) == 0);
                    if (peer == null)
                    {
                        await context.WriteLineToUserAsync($"No peer found with name '{words[1]}'.", cancellationToken);
                        return;
                    }

                    var sb = new StringBuilder();
                    sb.AppendLine("\r\nPEER INFO");
                    sb.AppendLine($"Short name    : {peer.ShortName}");
                    sb.AppendLine($"Thumbprint    : {(peer.IdentityPublicKeyThumbprint == null ? "(NULL)" : Convert.ToHexString(peer.IdentityPublicKeyThumbprint.Value.AsSpan()))}");
                    sb.AppendLine($"Endpoint      : {(peer.RemoteEndPoint == null ? "(NULL)" : peer.RemoteEndPoint.ToString())}");

                    sb.AppendLine("\r\n[Network]");
                    sb.AppendLine($"State         : {System.Enum.GetName(peer.State)}");
                    var rel = DateUtils.GetRelativeTimeString(DateTime.UtcNow - peer.LastActivity);
                    sb.AppendLine($"Last Activity : {peer.LastActivity} ({rel})");
                    sb.AppendLine($"Bytes sent    : {peer.BytesSent:n0} ({DisplayUtils.ConvertByteCountToRelativeSuffix(peer.BytesSent)})");
                    sb.AppendLine($"Bytes received: {peer.BytesReceived:n0} ({DisplayUtils.ConvertByteCountToRelativeSuffix(peer.BytesReceived)})");
                    sb.AppendLine($"My observed IP: {peer.ClientPerceivedLocalAddress}");

                    sb.AppendLine("\r\n[DHT]");
                    var distance = peer.IdentityPublicKeyThumbprint == null ? null : ByteUtils.GetDistanceMetric(IdentityKeyPublicThumbprint, peer.IdentityPublicKeyThumbprint.Value);
                    sb.AppendLine($"Distance      : {(distance == null ? "(NULL)" : Convert.ToHexString(distance.AsSpan()))}");
                    var kbucket = distance == null ? default(int?) : ByteUtils.MapDistanceToBucketNumber(distance, 256);
                    sb.AppendLine($"K-Bucket      : {(kbucket == null ? "(NULL)" : kbucket.Value)}");

                    sb.AppendLine().AppendLine("END OF PEER INFO").AppendLine();

                    await context.WriteLineToUserAsync(sb.ToString(), cancellationToken);
                    break;
                }

            case "peers":
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("\r\nPEER LIST");
                    var peers = Peers.Values;
                    if (peers.Count > 0)
                    {
                        var state_len = peers.Max(p => p.State.ToString().Length);
                        var rep_len = peers.Max(p => p.RemoteEndPoint == null ? 0 : p.RemoteEndPoint.ToString()!.Length);
                        var recv_len = peers.Max(p => p.RemoteEndPoint == null ? 0 : p.BytesReceived.ToString().PadRight("Recv".Length).Length);
                        var sent_len = peers.Max(p => p.RemoteEndPoint == null ? 0 : p.BytesSent.ToString().PadRight("Sent".Length).Length);
                        sb.AppendLine($"PeerShortName {"State".PadRight(state_len)} {"RemoteEndPoint".PadRight(rep_len)} {"Recv".PadRight(recv_len)} {"Sent".PadRight(sent_len)} IdPubKeyThumbprint");
                        foreach (var peer in peers)
                        {
                            sb.AppendLine($"{peer.ShortName.PadRight("PeerShortName".Length)} {peer.State.ToString().PadRight(state_len)} {(peer.RemoteEndPoint == null ? string.Empty.PadRight("RemoteEndPoint".Length) : peer.RemoteEndPoint.ToString()!).PadRight(rep_len)} {peer.BytesReceived.ToString().PadRight(recv_len)} {peer.BytesSent.ToString().PadRight(sent_len)} {(peer.IdentityPublicKeyThumbprint == null ? "(NULL)" : Convert.ToHexString(peer.IdentityPublicKeyThumbprint.Value.AsSpan()))}");
                        }
                    }
                    sb.AppendLine().AppendLine("END OF PEER LIST").AppendLine();
                    await context.WriteLineToUserAsync(sb.ToString(), cancellationToken);
                    break;
                }

            case "quit":
                await context.WriteLineToUserAsync("\r\nGOODBYE.", cancellationToken);
                User?.Close();
                User = null;
                Logger?.LogInformation("Console user quit.");
                return;

            case "shutdown":
                Logger?.LogCritical("Console user issued shutdown command.");
                Environment.Exit(0);
                return;

            default:
                foreach (var ca in ClientApps)
                {
                    // We support a few different types of command handling here:
                    // 1. The module name to drop into its targeted interactive mode, like
                    //    'fs' to target the fserve module.  In targeted mode, only 'fs'
                    //    commands will match, and which can make it easier to use if there are
                    //    cmomand conflicts named the same across different loaded modules.
                    // 2. MODULE + COMMAND, like fs login
                    // 3. MODULE+COMMAND, like fslogin (in case the user mistypes or wants a
                    //    shorter unambiguous command tareting
                    // 4. COMMAND, like 'ping', where it is unlikely to be a name conflict.

                    // HERE IS #1
                    if (two_word_command == null
                        && ca.InteractiveCommand != null
                        && string.Compare(ca.InteractiveCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        ActiveClientApp = ca;
                        await ca.OnActivate(cancellationToken);
                        return;
                    }

                    // HERE IS #2, #3, and #4.
                    var two_word_matches = ca.Commands
                        .Where(cc => string.Compare($"{ca.InteractiveCommand} {cc.InteractiveCommand}", two_word_command, StringComparison.InvariantCultureIgnoreCase) == 0)
                        .ToImmutableArray();

                    string[] words_parameters = two_word_matches.Length == 0
                        ? words
                        : words.Skip(1).ToArray();

                    var appCommandMatches = two_word_matches.Length == 0
                        ? ca.Commands.Where(cc =>
                            string.Compare($"{ca.InteractiveCommand}{cc.InteractiveCommand}", command, StringComparison.InvariantCultureIgnoreCase) == 0
                            || string.Compare(cc.InteractiveCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0
                        ).ToImmutableArray()
                        : two_word_matches;

                    if (appCommandMatches.Length == 1)
                    {
                        var appCommand = appCommandMatches[0];
                        var (success, errorMessage) = await appCommand.Invoke(words_parameters, cancellationToken);
                        if (!success)
                            await context.WriteLineToUserAsync($"ERROR: {(ActiveClientApp == null ? string.Empty : ActiveClientApp.InteractiveCommand + " ")}{appCommand.InteractiveCommand}: {errorMessage}", cancellationToken);
                        else if (!string.IsNullOrWhiteSpace(errorMessage))
                            await context.WriteLineToUserAsync(errorMessage, cancellationToken); // error might be a status message
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
        ArgumentNullException.ThrowIfNull(innerPayload);

        if (routingPeerThumbprint != null && routingPeerThumbprint.Value.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(routingPeerThumbprint), $"Thumbprints must be {Apps.Common.Constants.THUMBPRINT_LEN} bytes, but the one provided was {routingPeerThumbprint.Value.Length} bytes");
        if (ultimateDestinationThumbprint.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(ultimateDestinationThumbprint), $"Thumbprints must be {Apps.Common.Constants.THUMBPRINT_LEN} bytes, but the one provided was {ultimateDestinationThumbprint.Length} bytes");

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
                var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, [.. IdentityKeyPublicBytes]);
                var pri = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, [.. IdentityKeyPrivateBytes]);

                var nodeSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_87, true);
                nodeSigner.Init(true, pri);
                var packed_payload = Any.Pack(innerPayload);
                nodeSigner.BlockUpdate(packed_payload.ToByteArray());
                var signature = nodeSigner.GenerateSignature();

                return new ForwardedMessage
                {
                    ForwardId = forwardId,
                    Ttl = 20,
                    SrcIdentityThumbprint = ByteString.CopyFrom(IdentityKeyPublicThumbprint.AsSpan()),
                    DstIdentityThumbprint = ByteString.CopyFrom(ultimateDestinationThumbprint.AsSpan()),
                    Payload = packed_payload,
                    Signature = ByteString.CopyFrom(signature.AsSpan())
                };
            }
        }

        return null;
    }

    private DirectedMessage PrepareDirectedMessage(ImmutableArray<byte> destinationIdPubKeyThumbprint, IMessage payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (destinationIdPubKeyThumbprint.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(destinationIdPubKeyThumbprint), $"Thumbprint should be {Apps.Common.Constants.THUMBPRINT_LEN} bytes long but was {destinationIdPubKeyThumbprint.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        if (Enumerable.SequenceEqual(destinationIdPubKeyThumbprint, IdentityKeyPublicThumbprint))
            throw new ArgumentException("Attempted to prepare direct messages to my own node", nameof(destinationIdPubKeyThumbprint));

        var packed_payload = Any.Pack(payload);

        // If destined for loopback, then source is also loopback
        ByteString src;
        byte[] signature;
        if (destinationIdPubKeyThumbprint.All(b => b == 0x00))
        {
            src = ByteString.CopyFrom(destinationIdPubKeyThumbprint.AsSpan());
            signature = []; // No reason to sign loopback messages
        }
        else
        {
            src = ByteString.CopyFrom(IdentityKeyPublicThumbprint.AsSpan());

            var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, [.. IdentityKeyPublicBytes]);
            var pri = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, [.. IdentityKeyPrivateBytes]);

            var nodeSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_87, true);
            nodeSigner.Init(true, pri);
            nodeSigner.BlockUpdate(packed_payload.ToByteArray());
            signature = nodeSigner.GenerateSignature();
        }

        var dm = new DirectedMessage
        {
            // The source is my own node.
            SrcIdentityThumbprint = src,
            // The desitnation is some other node I know by its thumbprint.
            DstIdentityThumbprint = ByteString.CopyFrom(destinationIdPubKeyThumbprint.AsSpan()),
            Payload = packed_payload,
            Signature = ByteString.CopyFrom(signature.AsSpan()),
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

        foreach (var peer in Peers.Values.Where(p => !p.IsLoopback && p.State == PeerState.ESTABLISHED))
        {
            var envelope = peer.PrepareEnvelope(original, logger);
            await peer.SendEnvelope(envelope, logger, cancellationToken);
            Logger?.LogDebug("FORWARD to {PeerShortName} ({RemoteEndPoint}) intended for {DestinationThumbprint}: ForwardId={ForwardId}", peer.ShortName, peer.RemoteEndPoint, Convert.ToHexString(original.DstIdentityThumbprint.Span), original.ForwardId);
        }
    }

    internal void AdvisePeerPathToIdentity(Peer peer, ImmutableArray<byte>? thumbprint)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (!thumbprint.HasValue)
            throw new ArgumentNullException(nameof(thumbprint));

        if (thumbprint.Value.Length != Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(thumbprint), $"Thumbprint must be {Constants.THUMBPRINT_LEN} bytes long but was {thumbprint.Value.Length} bytes.  Did you pass in a full pub key instead of a thumbprint?");

        // This cache is keyed by string representations of thumbprints.
        // The cache value is the peer short name
        var cacheKey = Convert.ToHexString(thumbprint.Value.AsSpan());

        ThumbprintPeerPaths.Set(cacheKey, peer.ShortName, new MemoryCacheEntryOptions
        {
            SlidingExpiration = new TimeSpan(0, 15, 0) // For 15 minutes
        });
    }

    internal async Task RelayForwardMessage(ForwardedMessage original, ImmutableArray<byte>? excludedNeighborThumbprint, ILogger? logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(logger);

        if (excludedNeighborThumbprint != null && excludedNeighborThumbprint.Value.Length != Apps.Common.Constants.THUMBPRINT_LEN)
            throw new ArgumentOutOfRangeException(nameof(excludedNeighborThumbprint), $"Thumbprints must be {Apps.Common.Constants.THUMBPRINT_LEN} bytes, but the one provided was {excludedNeighborThumbprint.Value.Length} bytes");

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
            Logger?.LogDebug("FORWARD to {PeerShortName} ({RemoteEndPoint}) intended for {DestinationThumbprint}: ForwardId={ForwardId}", peer.ShortName, peer.RemoteEndPoint, Convert.ToHexString(relayed.DstIdentityThumbprint.Span), relayed.ForwardId);
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

    public (byte[] enc, string salt62) ExportKeyContainer(string? password)
    {
        var kc = new KeyContainer
        {
            PublicKeyBase64 = Convert.ToBase64String(IdentityKeyPublicBytes.AsSpan()),
            PrivateKeyBase64 = Convert.ToBase64String(IdentityKeyPrivateBytes.AsSpan())
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

    public async Task<bool> EnterAppInteractiveMode(string clientAppName, CancellationToken cancellationToken)
    {
        if (ActiveClientApp != null && string.Compare(ActiveClientApp.Name, clientAppName, StringComparison.Ordinal) == 0)
            return true; // Already active.

        foreach (var ca in ClientApps)
        {
            // Maybe it's a client app that has an interactive mode?
            if (string.Compare(ca.Name, clientAppName, StringComparison.Ordinal) == 0)
            {
                ActiveClientApp = ca;
                await ca.OnActivate(cancellationToken);
                return true;
            }
        }

        return false;
    }

    public async Task<bool> ExitAppInteractiveMode(string clientAppName, CancellationToken cancellationToken)
    {
        if (ActiveClientApp == null)
            return true; // Already not active

        if (ActiveClientApp != null && string.Compare(ActiveClientApp.Name, clientAppName, StringComparison.Ordinal) == 0)
        {
            await ActiveClientApp.OnDeactivate(cancellationToken);
            ActiveClientApp = null;
            return true;
        }

        return false;
    }

    internal PeerConnectedArgs RaisePeerConnected(Peer peer)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (peer.IdentityPublicKey == null)
            throw new ArgumentException($"{nameof(peer.IdentityPublicKey)} is null on peer", nameof(peer));
        if (peer.IdentityPublicKeyThumbprint == null)
            throw new ArgumentException($"{nameof(peer.IdentityPublicKeyThumbprint)} is null on peer", nameof(peer));
        if (peer.RemoteEndPoint == null)
            throw new ArgumentException($"{nameof(peer.RemoteEndPoint)} is null on peer", nameof(peer));

        var args = new PeerConnectedArgs(peer.IdentityPublicKey, peer.IdentityPublicKeyThumbprint, peer.RemoteEndPoint);
        PeerConnected?.Invoke(this, args);
        return args;
    }

    internal bool IsKnownInvalidSignature(
        ReadOnlySpan<byte> thumbprint,
        Func<byte[]> message,
        Func<byte[]> signature)
    {

        var thumbprintHex = Convert.ToHexString(thumbprint);
        if (!ThumbprintPublicKeyCache.TryGetValue(thumbprintHex, out ImmutableArray<byte> publicKey))
            return false;

        // This is a Func<> pattern so we don't actually convert messages/signatures unless we have the thumbprint in cache
        return !CryptoUtils.ValidateDilithiumSignature(publicKey, message.Invoke(), signature.Invoke());
    }
}