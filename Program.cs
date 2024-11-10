using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

internal class Program
{
    private static readonly ConcurrentDictionary<TaskEntry, Task> Tasks = [];
    private static readonly ConcurrentDictionary<PeerEntry, TcpClient> Peers = [];

    private async static Task Main(string[] args)
    {
        Console.WriteLine("Luxelot");
        Console.WriteLine("v0.0.1");

        using ILoggerFactory factory = LoggerFactory.Create(builder =>
            builder
            .AddFilter("Luxelot", LogLevel.Trace)
            .AddConsole());

        CancellationTokenSource cts = new();

        var alice = new Node("Alice", factory)
        {
            Port = 9000
        };
        var bob = new Node("Bob", factory)
        {
            Port = 9001,
            Phonebook = [
                new IPEndPoint(IPAddress.Loopback, 9000)
            ]
        };

        var tasks = new Task[]{
            Task.Run(async () => await alice.Main(cts.Token)),
            Task.Run(async () => await bob.Main(cts.Token))
        };
        Task.WaitAll(tasks, cts.Token); ;
    }
}