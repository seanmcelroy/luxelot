using System.Net;
using Microsoft.Extensions.Logging;

namespace Luxelot;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Luxelot");
        Console.WriteLine("v0.0.1");

        using ILoggerFactory factory = LoggerFactory.Create(builder =>
            builder
            .AddFilter("Luxelot", LogLevel.Trace)
            .AddFilter("Node", LogLevel.Trace)
            .AddConsole());

        CancellationTokenSource cts = new();

        var alice = new Node(factory, "Alice")
        {
            PeerPort = 9000,
            UserPort = 8000,
            Phonebook = [
                new IPEndPoint(IPAddress.Loopback, 9001) // Alice calls Bob
            ]
        };
        var bob = new Node(factory, "Bob")
        {
            PeerPort = 9001,
            UserPort = 8001,
            Phonebook = [
                new IPEndPoint(IPAddress.Loopback, 9002) // Bob calls Carol
            ]
        };
        var carol = new Node(factory, "Carol")
        {
            PeerPort = 9002,
            UserPort = 8002,
        };

        var tasks = new Task[]{
            Task.Run(() => alice.Main(cts.Token), cts.Token),
            Task.Run(() => bob.Main(cts.Token), cts.Token),
            Task.Run(() => carol.Main(cts.Token), cts.Token)
        };
        Task.WaitAll(tasks, cts.Token); ;
    }
}