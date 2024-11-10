using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Google.Protobuf;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;

internal class Node
{
    public const uint PROTOCOL_VERSION = 1;


    private readonly string Name;
    private readonly ILogger Logger;
    public required int Port { get; init; }
    public IPEndPoint[]? Phonebook { get; init; }

    private readonly ConcurrentDictionary<TaskEntry, Task> Tasks = [];
    private readonly ConcurrentDictionary<PeerEntry, TcpClient> Peers = [];

    public Node(string name, ILoggerFactory loggerFactory)
    {
        Name = name;
        Logger = loggerFactory.CreateLogger($"Node {Name}");
    }

    public async Task Main(CancellationToken cancellationToken)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Logger.LogInformation("Setting up peer listener loop");
        var peer_listener_task = Task.Run(async () =>
        {
            try
            {
                using TcpListener peer_listener = new(IPAddress.Any, Port);
                peer_listener.Start();
                Logger.LogInformation($"Listening for peers at {peer_listener.LocalEndpoint}");
                while (!cts.IsCancellationRequested)
                {
                    var peer = await peer_listener.AcceptTcpClientAsync(cancellationToken);
                    using (Logger.BeginScope($"New Peer {peer.Client.RemoteEndPoint}"))
                    {
                        Logger.LogDebug($"New peer connection from {peer.Client.RemoteEndPoint}");
                        var (publicKeyBytes, privateKeyBytes) = GenerateKeysForPeer();

                        var peerEntry = new PeerEntry
                        {
                            RemoteEndpoint = peer.Client.RemoteEndPoint!,
                            PublicKey = publicKeyBytes,
                            PrivateKey = privateKeyBytes,
                            SharedKey = null, // Established after Ack
                        };
                        Peers.TryAdd(peerEntry, peer);
                        Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ProcessSyn(peerEntry, peer, cancellationToken)));
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Exception in peer listener loop");
                throw;
            }
        });
        var peer_listener_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
        Tasks.TryAdd(peer_listener_task_entry, peer_listener_task);
        Logger.LogInformation($"Peer listener loop is a persistent background worker TaskId={peer_listener_task_entry.TaskId}");

        Logger.LogInformation("Setting up peer janitor loop");
        var peer_janitor_task = Task.Run(() =>
        {
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    Thread.Sleep(60000); // Janitor runs once per minute.
                    foreach ((PeerEntry peerEntry, TcpClient peer) in Peers)
                    {
                        var peer_tcp_info = IPGlobalProperties.GetIPGlobalProperties()
                                .GetActiveTcpConnections()
                                .SingleOrDefault(x => x.LocalEndPoint.Equals(peer.Client.LocalEndPoint)
                                                    && x.RemoteEndPoint.Equals(peer.Client.RemoteEndPoint)
                                );
                        var peer_state = peer_tcp_info != null ? peer_tcp_info.State : TcpState.Unknown;
                        if (peer_state != TcpState.Established || !peer.Client.Connected || !peer.GetStream().CanWrite)
                            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peerEntry, peer)));
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Exception in peer listener loop");
                throw;
            }
        });
        var peer_janitor_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
        Tasks.TryAdd(peer_janitor_task_entry, peer_janitor_task);
        Logger.LogInformation($"Peer janitor loop is a persistent background worker TaskId={peer_janitor_task_entry.TaskId}");

        if (Phonebook?.Length > 0)
        {

        }

        Logger.LogInformation("Setting up dialer loop");
        var dialer_task = Task.Run(async () =>
        {
            while (Phonebook == null || Phonebook.Length == 0)
            {
                // Sleep for one hour.
                Thread.Sleep(60 * 60000);
            }

            try
            {
                Thread.Sleep(5000); // Dialer starts after 5 seconds.
                do
                {
                    foreach (var endpoint in Phonebook)
                    {
                        TcpClient peer = new();
                        await peer.ConnectAsync(endpoint, cancellationToken);

                        var (publicKeyBytes, privateKeyBytes) = GenerateKeysForPeer();

                        var peerEntry = new PeerEntry
                        {
                            RemoteEndpoint = peer.Client.RemoteEndPoint!,
                            PublicKey = publicKeyBytes,
                            PrivateKey = privateKeyBytes,
                            SharedKey = null, // Established after Ack
                        };
                        Peers.TryAdd(peerEntry, peer);
                        Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => SendSyn(peerEntry, peer, cancellationToken)));
                    }

                    foreach ((PeerEntry peerEntry, TcpClient peer) in Peers)
                    {
                        var peer_tcp_info = IPGlobalProperties.GetIPGlobalProperties()
                                .GetActiveTcpConnections()
                                .SingleOrDefault(x => x.LocalEndPoint.Equals(peer.Client.LocalEndPoint)
                                                    && x.RemoteEndPoint.Equals(peer.Client.RemoteEndPoint)
                                );
                        var peer_state = peer_tcp_info != null ? peer_tcp_info.State : TcpState.Unknown;
                        if (peer_state != TcpState.Established || !peer.Client.Connected || !peer.GetStream().CanWrite)
                            Tasks.TryAdd(new TaskEntry { EventType = TaskEventType.FireOnce }, Task.Run(() => ShutdownPeer(peerEntry, peer)));
                    }
                    Thread.Sleep(5 * 60000); // Dialer then runs every 5 minutes.
                } while (!cts.IsCancellationRequested);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Exception in dialer loop");
                throw;
            }
        });
        var dialer_task_entry = new TaskEntry { EventType = TaskEventType.PersistentBackgroundWorker };
        Tasks.TryAdd(dialer_task_entry, dialer_task);
        Logger.LogInformation($"Dialer loop is a persistent background worker TaskId={dialer_task_entry.TaskId}");


        while (!cts.IsCancellationRequested)
        {
            if (Thread.Yield())
                Thread.Sleep(200);

            int taskQueueSkip = 0;

        // Task walk
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
                                Logger.LogError($"Persistent background worker is not alive TaskId={t.Key.TaskId}");
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
                                Logger.LogDebug($"Removed completed task {t.Key.TaskId}");
                                taskQueueSkip = taskIndex;
                                goto task_walk_again;
                            }
                            else
                            {
                                // logger.LogError($"Cannot remove completed task {t.Key.TaskId}!");
                            }

                            break;
                        }
                }

            }
        }
    }

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
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Unable to generate Kyber keypair");
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

            Logger.LogInformation($"Generated private key length: {privateKeyBytes.Length}");
            publicKeyBytes = CryptoUtils.GetChrystalsKyberPublicKeyFromEncoded(node_key);
            Logger.LogInformation($"Generated public key length: {publicKeyBytes.Length}");

            Logger.LogInformation("Key pairs successfully generated");
        }

        return (publicKeyBytes, privateKeyBytes);
    }

    private async Task SendSyn(PeerEntry peerEntry, TcpClient peer, CancellationToken cancellationToken)
    {
        if (peer.Connected)
        {
            var stream = peer.GetStream();
            if (stream.CanWrite)
            {
                Logger.LogDebug($"Sending Syn to peer {peer.Client.RemoteEndPoint}");
                var message = new Syn
                {
                    ProtVer = PROTOCOL_VERSION,
                    PubKey = ByteString.CopyFrom(peerEntry.PublicKey),
                };
                await stream.WriteAsync(message.ToByteArray(), cancellationToken);
            }
        }
    }

    private async Task ProcessSyn(PeerEntry peerEntry, TcpClient peer, CancellationToken cancellationToken)
    {
        // We have received a Syn (with a public key).  Calculate the Kyber cipher text and send back an Ack.
        if (!peer.Connected)
            return;

        var stream = peer.GetStream();
        if (!stream.CanRead || !stream.CanWrite)
            return;

        Syn syn = new();
        var syn_size = syn.CalculateSize();
        var buffer = new byte[syn_size];
        await stream.ReadExactlyAsync(buffer, 0, syn_size, cancellationToken);
        syn = Syn.Parser.ParseFrom(buffer);

        using var scope = Logger.BeginScope($"Process Syn from {peer.Client.RemoteEndPoint}");
        KyberPublicKeyParameters peer_public = new(KyberParameters.kyber1024, syn.PubKey.ToByteArray());
        var secretKeyWithEncapsulationSender = CryptoUtils.GenerateChrystalsKyberEncryptionKey(peer_public);

        // Shared Key
        var encryptionKey = secretKeyWithEncapsulationSender.GetSecret();
        peerEntry.SharedKey = encryptionKey;

        // Cipher text
        var encapsulatedKey = secretKeyWithEncapsulationSender.GetEncapsulation();

        Logger.LogDebug($"Sending Ack to peer {peer.Client.RemoteEndPoint}");
        var message = new Ack
        {
            ProtVer = PROTOCOL_VERSION,
            CipherText = ByteString.CopyFrom(encapsulatedKey),
        };
        await stream.WriteAsync(message.ToByteArray(), cancellationToken);
    }

    private void ShutdownPeer(PeerEntry peerEntry, TcpClient peer)
    {
        if (Peers.TryRemove(new KeyValuePair<PeerEntry, TcpClient>(peerEntry, peer)))
            Logger.LogDebug($"Removed dead peer {peer.Client.RemoteEndPoint}");
        else
            Logger.LogError($"Dead peer {peer.Client.RemoteEndPoint}!");
    }
}