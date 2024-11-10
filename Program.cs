using System.Net;
using Microsoft.Extensions.Logging;

internal class Program
{
    private async static Task Main(string[] args)
    {
        Console.WriteLine("Luxelot");
        Console.WriteLine("v0.0.1");

        using ILoggerFactory factory = LoggerFactory.Create(builder =>
            builder
            .AddFilter("Luxelot", LogLevel.Trace)
            .AddFilter("Node", LogLevel.Trace)
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
            Task.Run(async () => await alice.Main(cts.Token), cts.Token),
            Task.Run(async () => await bob.Main(cts.Token), cts.Token)
        };
        Task.WaitAll(tasks, cts.Token); ;
    }
}