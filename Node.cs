using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Luxelot;

public partial class Node
{
    public const uint PROTOCOL_VERSION = 1;

    private readonly ILogger Logger;
    public required int PeerPort { get; init; }
    public required int UserPort { get; init; }
    public IPEndPoint[]? Phonebook { get; init; }

    private readonly ConcurrentDictionary<TaskEntry, Task> Tasks = [];
    private readonly ConcurrentDictionary<EndPoint, Peer> Peers = [];
    private readonly ConcurrentDictionary<string, ImmutableArray<byte>> ThumbnailSignatureCache = [];
    internal TcpClient? User;
    private readonly Mutex UserMutex = new();
    private readonly AsymmetricCipherKeyPair IdentityKeys;
    public readonly ImmutableArray<byte> IdentityKeyPublicBytes;
    public readonly ImmutableArray<byte> IdentityKeyPublicThumbprint;
    public string Name { get; init; }
    public string ShortName { get; init; }

    public Node(ILoggerFactory loggerFactory, string? shortName)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);

        IdentityKeys = CryptoUtils.GenerateDilithiumKeyPair();
        var identityKeysPublicBytes = ((DilithiumPublicKeyParameters)IdentityKeys.Public).GetEncoded();
        IdentityKeyPublicBytes = [.. identityKeysPublicBytes];
        IdentityKeyPublicThumbprint = [.. SHA256.HashData(identityKeysPublicBytes)];
        Name = CryptoUtils.BytesToHex(IdentityKeyPublicThumbprint);
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
    }

    public void Main(CancellationToken cancellationToken)
    {
        var nodeContext = new NodeContext(this)
        {
            NodeShortName = ShortName,
            NodeIdentityKeyPublicBytes = IdentityKeyPublicBytes,
            NodeIdentityKeyPublicThumbprint = IdentityKeyPublicThumbprint,
            Logger = Logger,
        };

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

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
                        }

                        User = user;
                    }
                    finally
                    {
                        UserMutex.ReleaseMutex();
                    }

                    // User input handler loop
                    await User.GetStream().WriteAsync(Encoding.UTF8.GetBytes($"\r\nHELLO.\r\n"), cancellationToken);

                    var user_okay = true;
                    while (!cancellationToken.IsCancellationRequested && user_okay)
                    {
                        var buffer = new byte[1024]; // 1 kb
                        int size = 0;
                        try
                        {
                            size = await User.GetStream().ReadAsync(buffer, cancellationToken: cancellationToken);
                        }
                        catch (EndOfStreamException ex)
                        {
                            Logger.LogWarning(ex, "End of stream from user {RemoteEndPoint} could be processed. Closing.", User.Client?.RemoteEndPoint);
                            User.Close();
                            user_okay = false;
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
                    var added = Peers.TryAdd(peer.RemoteEndPoint!, peer);
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
                            ThumbnailSignatureCache.TryAdd(CryptoUtils.BytesToHex(peer.IdentityPublicKeyThumbprint), peer.IdentityPublicKey.Value);

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
                    TcpClient peerTcpClient = new();
                    await peerTcpClient.ConnectAsync(endpoint, cancellationToken);
                    var peer = Peer.CreatePeerToConnect(peerTcpClient, Logger);
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
                var shutdown = !await peer.HandleInputAsync(context, ThumbnailSignatureCache, cancellationToken);
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
                    ThumbnailSignatureCache.TryAdd(CryptoUtils.BytesToHex(peer.IdentityPublicKeyThumbprint), peer.IdentityPublicKey.Value);

                    // Okay, we made it!
                    Logger.LogDebug("Sending test message to peer {PeerShortName} ({RemoteEndPoint}) thumbprint {Thumbprint}", peer.PeerShortName, peer.RemoteEndPoint, CryptoUtils.BytesToHex(peer.IdentityPublicKeyThumbprint!));

                    var payload = new ConsoleAlert
                    {
                        Message = "WE DID IT!"
                    };
                    try
                    {
                        var directed = PrepareDirectedMessage(peer.IdentityPublicKeyThumbprint.Value, payload);
                        var envelope = peer.PrepareEnvelope(context, directed);
                        await peer.SendEnvelope(context, envelope, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError(ex, "Failed to send sample message; closing down connection to victim {PeerShortName} ({RemoteEndPoint}).", peer.PeerShortName, peer.RemoteEndPoint);
                        peer.Close();
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
                var cmds = new string[] { "node", "peers", "ping" };
                var cmd_string = cmds.Order().Aggregate((c, n) => $"{c}\r\n{n}");
                await context.WriteLineToUserAsync(cmd_string, cancellationToken);
                break;
            case "node":
                await context.WriteLineToUserAsync($"ID Public Key: {CryptoUtils.BytesToHex(IdentityKeyPublicThumbprint)}", cancellationToken);
                break;
            case "peers":
                await context.WriteLineToUserAsync("Peer List", cancellationToken);

                var rep_len = Peers.IsEmpty ? 0 : Peers.Values.Max(p => p.RemoteEndPoint == null ? 0 : p.RemoteEndPoint.ToString()!.Length);

                await context.WriteLineToUserAsync($"PeerShortName {"RemoteEndPoint".PadRight(rep_len)} Recv Sent IdPubKeyThumbprint", cancellationToken);

                foreach (var peer in Peers.Values)
                {
                    await context.WriteLineToUserAsync($"{peer.PeerShortName.PadRight("PeerShortName".Length)} {(peer.RemoteEndPoint == null ? string.Empty : peer.RemoteEndPoint.ToString()).PadRight(rep_len)} {peer.BytesReceived} {peer.BytesSent} {CryptoUtils.BytesToHex(peer.IdentityPublicKeyThumbprint)}", cancellationToken);
                }
                await context.WriteLineToUserAsync("End of Peer List", cancellationToken);
                break;

            case "ping":
                if (words.Length != 2 && words.Length != 3)
                    await context.WriteLineToUserAsync($"PING command requires one or two arguments, the peer name to direct the ping, and optionally a second parameter which is the THUMBPRINT for the actual intended recipient if different and you want to source route it.", cancellationToken);
                else
                {
                    var peer_to_ping = Peers.Values.FirstOrDefault(p => string.Compare(p.PeerShortName, words[1], StringComparison.OrdinalIgnoreCase) == 0);
                    if (peer_to_ping == null)
                        await context.WriteLineToUserAsync($"No peer found with name '{words[1]}'.", cancellationToken);
                    else
                    {
                        ImmutableArray<byte>? ping_target = words.Length == 2 ? null : [.. CryptoUtils.HexToBytes(words[2])];
                        var success = await peer_to_ping.SendPing(context, ping_target, cancellationToken);
                    }
                }
                break;

            case "shutdown":
                Environment.Exit(0);
                break;
        }

    }

    private void ShutdownPeer(Peer peer)
    {
        ArgumentNullException.ThrowIfNull(peer);

        if (peer.RemoteEndPoint != null && Peers.TryRemove(new KeyValuePair<EndPoint, Peer>(peer.RemoteEndPoint, peer)))
            Logger.LogDebug("Removed dead peer {PeerShortName} RemoteEndPoint {RemoteEndPoint}", peer.PeerShortName, peer.RemoteEndPoint);
        else
            Logger.LogError("Dead peer {PeerShortName} RemoteEndPoint {RemoteEndPoint}!", peer.PeerShortName, peer.RemoteEndPoint);
    }

    public DirectedMessage PrepareDirectedMessage(ImmutableArray<byte> destinationIdPubKeyThumbprint, IMessage payload)
    {
        ArgumentNullException.ThrowIfNull(destinationIdPubKeyThumbprint);
        ArgumentNullException.ThrowIfNull(payload);

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

    public async Task ForwardDirectedMessage(ImmutableArray<byte> destinationIdPubKeyThumbprint, IMessage payload) {

    }

    public IEnumerable<ImmutableArray<byte>> GetNeighborThumbprints() =>
        Peers.Where(p => p.Value.IdentityPublicKeyThumbprint != null)
            .Select(p => p.Value.IdentityPublicKeyThumbprint!.Value);

    [GeneratedRegex("(?:^|\\s)(\\\"(?:[^\\\"])*\\\"|[^\\s]*)")]
    private static partial Regex QuotedWordArrayRegex();
}