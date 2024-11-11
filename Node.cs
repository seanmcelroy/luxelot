using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Google.Protobuf;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Luxelot;

internal partial class Node
{
    public const uint PROTOCOL_VERSION = 1;

    private readonly string Name;
    private readonly ILogger Logger;
    public required int PeerPort { get; init; }
    public required int UserPort { get; init; }
    public IPEndPoint[]? Phonebook { get; init; }

    private readonly ConcurrentDictionary<TaskEntry, Task> Tasks = [];
    private readonly ConcurrentDictionary<Guid, Peer> Peers = [];
    private TcpClient? User;
    private readonly Mutex UserMutex = new();
    private readonly AsymmetricCipherKeyPair IdentityKeys;

    public byte[] IdentityKeyPublicBytes { get => ((DilithiumPublicKeyParameters)IdentityKeys.Public).GetEncoded(); }

    public Node(string name, ILoggerFactory loggerFactory)
    {
        Name = name;
        Logger = loggerFactory.CreateLogger($"Node {Name}");

        Logger.LogInformation("Generating node identity keys");
        IdentityKeys = CryptoUtils.GenerateDilithiumKeyPair();
        Logger.LogTrace("Node {NodeName} public identity key: {IdentityPublicKey}", Name, CryptoUtils.BytesToHex(IdentityKeyPublicBytes));
    }

    public void Main(CancellationToken cancellationToken)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Logger.LogInformation("Setting up user listener loop");
        {
            var user_listener_task = Task.Run(async () => await UserListenerTask(cts.Token), cancellationToken);
            var user_listener_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(user_listener_task_entry, user_listener_task);
            Logger.LogInformation("User listener loop is a persistent background worker task {TaskId}", user_listener_task_entry.TaskId);
        }

        Logger.LogInformation("Setting up peer listener loop");
        {
            var peer_listener_task = Task.Run(async () => await PeerListenerTask(cts.Token), cancellationToken);
            var peer_listener_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_listener_task_entry, peer_listener_task);
            Logger.LogInformation("Peer listener loop is a persistent background worker task {TaskId}", peer_listener_task_entry.TaskId);
        }

        Logger.LogInformation("Setting up peer janitor loop");
        {
            var peer_janitor_task = Task.Run(() => PeerJanitorTask(cts.Token), cancellationToken);
            var peer_janitor_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_janitor_task_entry, peer_janitor_task);
            Logger.LogInformation("Peer janitor loop is a persistent background worker task {TaskId}", peer_janitor_task_entry.TaskId);
        }

        Logger.LogInformation("Setting up peer dialer loop");
        {
            var peer_dialer_task = Task.Run(() => PeerDialerTask(cts.Token), cancellationToken);
            var dialer_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(dialer_task_entry, peer_dialer_task);
            Logger.LogInformation("Dialer loop is a persistent background worker task {TaskId}", dialer_task_entry.TaskId);
        }

        Logger.LogInformation("Setting up peer connected input handler loop");
        {
            var peer_handler_task = Task.Run(() => PeerHandleInputTask(cts.Token), cancellationToken);
            var peer_handler_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
            Tasks.TryAdd(peer_handler_task_entry, peer_handler_task);
            Logger.LogInformation("Peer input handler loop is a persistent background worker task {TaskId}", peer_handler_task_entry.TaskId);
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
                                Logger.LogDebug("Removed completed task {TaskId}", t.Key.TaskId);
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
    private async Task UserListenerTask(CancellationToken cancellationToken)
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
                        await HandleUserInput(input);
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
    private async Task PeerListenerTask(CancellationToken cancellationToken)
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
                    var added = Peers.TryAdd(peer.PeerId, peer);
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(async () =>
                    {
                        var shutdown = !await peer.HandleSyn(IdentityKeyPublicBytes, Logger, cancellationToken);
                        if (shutdown)
                            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
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
    private async Task PeerDialerTask(CancellationToken cancellationToken)
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
                    var added = Peers.TryAdd(peer.PeerId!, peer);
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => SendSyn(peer, cancellationToken), cancellationToken));
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

    private async Task PeerHandleInputTask(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            if (Thread.Yield())
                Thread.Sleep(200);

            // Peer walk
            foreach (var peer in Peers.Values)
            {
                var shutdown = !await peer.HandleInputAsync(Logger, cancellationToken);
                if (shutdown)
                {
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                    continue;
                }
            }
        }
    }

    #endregion


    private (byte[] publicKeyBytes, byte[] privateKeyBytes) GenerateKeysForPeer()
    {
        //byte[] encryptionKey, encapsulatedKey, decryptionKey;
        byte[] publicKeyBytes, privateKeyBytes;

        using (Logger.BeginScope($"Crypto setup"))
        {
            // Generate Kyber crypto material for our comms with this peer.
            Logger.LogInformation("Generating cryptographic key material");
            AsymmetricCipherKeyPair node_key;
            try
            {
                node_key = CryptoUtils.GenerateKyberKeyPair();
                Logger.LogDebug("Geneated Kyber key pair!");
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Unable to generate Kyber key pair");
                throw;
            }

            // Generate the encryption key and the encapsulated key
            //var secretKeyWithEncapsulationSender = CryptoUtils.GenerateChrystalsKyberEncryptionKey((KyberPublicKeyParameters)node_key.Public);
            //encryptionKey = secretKeyWithEncapsulationSender.GetSecret();
            //encapsulatedKey = secretKeyWithEncapsulationSender.GetEncapsulation();

            //logger.LogInformation("Encryption side: generate the encryption key and the encapsulated key\r\n"
            //+ $"Encryption key length: {encryptionKey.Length} key: {CryptoUtils.BytesToHex(encryptionKey)}\r\n"
            //+ $"Encapsulated key length: {encapsulatedKey.Length} key: {CryptoUtils.BytesToHex(encapsulatedKey)}");

            privateKeyBytes = CryptoUtils.GetChrystalsKyberPrivateKeyFromEncoded(node_key);
            //decryptionKey = CryptoUtils.GenerateChrystalsKyberDecryptionKey(privateKeyBytes, encapsulatedKey);
            //var keysAreEqual = Enumerable.SequenceEqual(encryptionKey, decryptionKey);

            //logger.LogInformation("Decryption side: receive the encapsulated key and generate the decryption key\r\n"
            //    + $"Decryption key length: {decryptionKey.Length} key: {CryptoUtils.BytesToHex(decryptionKey)}"
            //    + $"Decryption key is equal to encryption key: {keysAreEqual}");

            Logger.LogTrace("Generated private key length: {PrivateKeyByteLength}", privateKeyBytes.Length);
            publicKeyBytes = CryptoUtils.GetChrystalsKyberPublicKeyFromEncoded(node_key);
            Logger.LogTrace("Generated public key length: {PublicKeyByteLength}", publicKeyBytes.Length);

            Logger.LogDebug("Key pairs successfully generated");
        }

        return (publicKeyBytes, privateKeyBytes);
    }

    private async Task SendSyn(Peer peer, CancellationToken cancellationToken)
    {
        if (peer.IsWriteable)
        {
            var stream = peer.GetStream();
            Logger.LogDebug("Sending Syn to peer {PeerId} ({RemoteEndPoint})", peer.PeerId, peer.RemoteEndPoint);
            var message = new Syn
            {
                ProtVer = PROTOCOL_VERSION,
                SessionPubKey = ByteString.CopyFrom(peer.SessionPublicKey),
                IdPubKey = ByteString.CopyFrom(IdentityKeyPublicBytes)
            };
            await stream.WriteAsync(message.ToByteArray(), cancellationToken);
            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(async () =>
            {
                var shutdown = !await peer.HandleAck(Logger, cancellationToken);
                if (shutdown)
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));

                // Okay, we made it!
                Logger.LogDebug("Sending test message to peer {PeerId} ({RemoteEndPoint})", peer.PeerId, peer.RemoteEndPoint);
                byte[] payload = Encoding.UTF8.GetBytes("WE DID IT!");
                try
                {
                    var directed = PrepareDirectedMessage(peer.IdentityPublicKeyThumbprint, payload, Logger);
                    var envelope = peer.PrepareEnvelope(directed.ToByteArray(), Logger);
                    await peer.GetStream().WriteAsync(envelope.ToByteArray(), cancellationToken);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Failed to send sample message; closing down connection to victim {PeerId} ({RemoteEndPoint}).", peer.PeerId, peer.RemoteEndPoint);
                    peer.Close();
                    Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peer), cancellationToken));
                }

            }, cancellationToken));
        }
    }

    private async Task HandleUserInput(string input)
    {
        input = input.Trim(' ', '\r', '\n');
        if (input.Length == 0)
            return;

        //Logger.LogTrace($"USER INPUT: '{input}'");
        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();
        var stream = User.GetStream();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                var cmds = new string[] { "node", "peers", "ping" };
                var cmd_string = cmds.Aggregate((c, n) => $"{c}\r\n{n}");
                await stream.WriteAsync(Encoding.UTF8.GetBytes($"{cmd_string}\r\n"));
                break;
            case "node":
                await stream.WriteAsync(Encoding.UTF8.GetBytes($"ID Public Key: {CryptoUtils.BytesToHex(IdentityKeyPublicBytes.Take(10))}\r\n"));
                break;
            case "peers":
                await stream.WriteAsync(Encoding.UTF8.GetBytes("Peer List\r\n"));
                await stream.WriteAsync(Encoding.UTF8.GetBytes("PeerId RemoteEndPoint BytesReceived PeerIDKeyFingerprint\r\n"));
                foreach (var peer in Peers.Values)
                {
                    await stream.WriteAsync(Encoding.UTF8.GetBytes($"{peer.PeerId} {peer.RemoteEndPoint} {peer.BytesReceived}(r) {CryptoUtils.BytesToHex(peer.IdentityPublicKeyThumbprint)}\r\n"));
                }
                await stream.WriteAsync(Encoding.UTF8.GetBytes("End of Peer List\r\n"));
                break;

            case "ping":
                if (words.Length != 2)
                    await stream.WriteAsync(Encoding.UTF8.GetBytes($"PING command requires one argument, the PeerId to direct the ping.\r\n"));
                else if (!Guid.TryParse(words[1], out Guid destPeerId))
                    await stream.WriteAsync(Encoding.UTF8.GetBytes($"Arg 1 is not a GUID.\r\n"));
                else
                {
                    var peer_to_ping = Peers.Values.SingleOrDefault(p => p.PeerId.Equals(destPeerId));
                    if (peer_to_ping == null)
                        await stream.WriteAsync(Encoding.UTF8.GetBytes($"No peer found with GUID {destPeerId}.\r\n"));
                    else
                    {
                        var ping = new Messages.Ping
                        {
                            Identifier = 1,
                            Sequence = 1,
                            Payload = null
                        };
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
        if (Peers.TryRemove(new KeyValuePair<Guid, Peer>(peer.PeerId, peer)))
            Logger.LogDebug("Removed dead peer {PeerId} RemoteEndPoint {RemoteEndPoint}", peer.PeerId, peer.RemoteEndPoint);
        else
            Logger.LogError("Dead peer {PeerId} RemoteEndPoint {RemoteEndPoint}!", peer.PeerId, peer.RemoteEndPoint);
    }

    public DirectedMessage PrepareDirectedMessage(byte[] destinationIdPubKeyThumbprint, byte[] payload, ILogger logger)
    {
        var nodeIdPrivateKey = (DilithiumPrivateKeyParameters)IdentityKeys.Private;
        var nodeSigner = new DilithiumSigner();
        nodeSigner.Init(true, nodeIdPrivateKey);
        var signature = nodeSigner.GenerateSignature(payload);

        return new DirectedMessage
        {
            // The source is my own node.
            SrcIdentityPublicKeyThumbprint = ByteString.CopyFrom(SHA256.HashData(IdentityKeyPublicBytes)),
            // The desitnation is some other node I know by its thumbprint.
            DstIdentityPublicKeyThumbprint = ByteString.CopyFrom(destinationIdPubKeyThumbprint),
            Payload = ByteString.CopyFrom(payload),
            Signature = ByteString.CopyFrom(signature),
        };
    }

    [GeneratedRegex("(?:^|\\s)(\\\"(?:[^\\\"])*\\\"|[^\\s]*)")]
    private static partial Regex QuotedWordArrayRegex();
}