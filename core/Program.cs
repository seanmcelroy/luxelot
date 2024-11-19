using System.Net;
using Luxelot.Config;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Luxelot;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Luxelot v0.0.1");
        CancellationTokenSource cts = new();

        // Setup hosting
        var hostBuilder = Host.CreateApplicationBuilder(args);

        IConfigurationRoot config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .AddEnvironmentVariables()
            .Build();

        hostBuilder.Configuration.AddConfiguration(config);
        hostBuilder.Logging.AddConfiguration(config);
        using IHost host = hostBuilder.Build();

        var loggingFactory = (ILoggerFactory?)host.Services.GetService(typeof(ILoggerFactory));
        if (loggingFactory == null)
        {
            Console.Error.WriteLine("Unable to initialize logging service.");
            Environment.Exit(-1);
        }

        // Configuration settings
        var nodesConfig = hostBuilder.Configuration.GetSection(nameof(Nodes)).Get<Nodes>();
        if (nodesConfig == null)
        {
            Console.Error.WriteLine("Unable to get Nodes configuration from settings.");
            Environment.Exit(-2);
        }

        List<Node> nodes = [];
        foreach (var node in nodesConfig.Instances)
        {
            nodes.Add(new Node(loggingFactory, node.Key)
            {
                ListenAddress = IPAddress.Parse(node.Value.ListenAddress),
                PeerPort = node.Value.PeerPort,
                UserPort = node.Value.UserPort,
                Phonebook = node.Value.KnownPeers == null ? [] : node.Value.KnownPeers.Select(k => IPEndPoint.Parse(k)).ToArray()
            });
        }

        List<Task> taskList = [];
        taskList.Add(host.RunAsync(cts.Token));
        foreach (var node in nodes)
            taskList.Add(Task.Run(() => node.Main(cts.Token), cts.Token));
        Task.WaitAll([.. taskList], cts.Token); ;
    }
}