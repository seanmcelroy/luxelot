using System.Net;
using Luxelot.Config;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Luxelot;

internal class Program
{
    private static async Task Main(string[] args)
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
        var logger = loggingFactory.CreateLogger("Program");

        // Configuration settings
        logger.LogInformation("Reading nodes configuration");
        var nodesConfig = hostBuilder.Configuration.GetSection(nameof(Nodes)).Get<Nodes>();
        if (nodesConfig == null)
        {
            logger.LogError("Unable to get Nodes configuration from settings.");
            Environment.Exit(-2);
        }

        var appDataFolders = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!Directory.Exists(appDataFolders))
        {
            logger.LogError("Unable to find system application data folder root at: {Path}", appDataFolders);
            Environment.Exit(-3);
        }
        var luxelotDataFolder = Path.Combine(appDataFolders, "luxelot");
        if (!Directory.Exists(luxelotDataFolder))
        {
            logger.LogError("Unable to find Luxelot data folder, creating it at: {Path}", luxelotDataFolder);
            Directory.CreateDirectory(luxelotDataFolder);
        }

        // Setup nodes
        logger.LogInformation("Creating nodes");

        var noPassword = config.GetValue("NoPassword", false);

        List<Node> nodes = [];
        foreach (var node in nodesConfig.Instances)
        {
            // Load key container
            if (node.Value.KeyContainer == null)
            {
                logger.LogInformation("No KeyContainer profiled for node {NodeShortName}. Creating new cryptographic key material.", node.Key);
                nodes.Add(new Node(host, node.Key)
                {
                    ListenAddress = IPAddress.Parse(node.Value.ListenAddress),
                    PeerPort = node.Value.PeerPort,
                    UserPort = node.Value.UserPort,
                    Phonebook = node.Value.KnownPeers == null ? [] : node.Value.KnownPeers.Select(k => IPEndPoint.Parse(k)).ToArray()
                });
            }
            else
            {
                var keyContainerFiles = Directory.GetFiles(luxelotDataFolder, $"{node.Value.KeyContainer}.*");
                string keyContainerFile;
                switch (keyContainerFiles.Length)
                {
                    case 0:
                        {
                            logger.LogWarning("Missing key container file found for node '{NodeShortName}'. Creating anew.", node.Key);
                            var newNode = new Node(host, node.Key)
                            {
                                ListenAddress = IPAddress.Parse(node.Value.ListenAddress),
                                PeerPort = node.Value.PeerPort,
                                UserPort = node.Value.UserPort,
                                Phonebook = node.Value.KnownPeers == null ? [] : node.Value.KnownPeers.Select(k => IPEndPoint.Parse(k)).ToArray(),
                            };

                            if (!noPassword) Console.WriteLine($"{Environment.NewLine}Enter a password to encrypt the key container for node '{node.Key}'.  You must enter this each time you start the app to run the node with the same ID.");
                            var password = noPassword ? "insecure" : ReadPassword();
                            var (enc, salt62) = newNode.ExportKeyContainer(password);
                            await File.WriteAllBytesAsync(Path.Combine(luxelotDataFolder, $"{node.Value.KeyContainer}.{salt62}"), enc, cts.Token);

                            nodes.Add(newNode);
                            continue;
                        }
                    case 1:
                        {
                            keyContainerFile = keyContainerFiles[0];
                            var enc = await File.ReadAllBytesAsync(keyContainerFile, cts.Token);
                            var salt62 = Path.GetExtension(keyContainerFile)[1..];

                            Node? newNode;
                            do
                            {
                                if (!noPassword) Console.WriteLine($"{Environment.NewLine}Enter the password to decrypt the key container for node '{node.Key}'.");
                                var password = noPassword ? "insecure" : ReadPassword();
                                newNode = Node.CreateFromEncryptedKeyContainer(
                                    logger,
                                    loggingFactory,
                                    enc,
                                    salt62,
                                    password,
                                    IPAddress.Parse(node.Value.ListenAddress),
                                    node.Value.PeerPort,
                                    node.Value.UserPort,
                                    node.Value.KnownPeers == null ? [] : node.Value.KnownPeers.Select(k => IPEndPoint.Parse(k)).ToArray()
                               );
                                if (newNode == null)
                                    await Console.Error.WriteLineAsync($"Incorrect password or other error creating the new from the key store file {keyContainerFile}");
                            } while (newNode == null);

                            logger.LogInformation("Loaded node '{NodeShortName}' from key container file: '{File}'", newNode.Name, keyContainerFile);
                            nodes.Add(newNode);
                            break;
                        }
                    default:
                        logger.LogWarning("Multiple key container files found for node {NodeShortName}. Choosing newest and deleting others.", node.Key);
                        break;
                }


            }

        }

        logger.LogInformation("Setting up primary host and node loops");
        List<Task> taskList = [];
        taskList.Add(host.RunAsync(cts.Token)); // Host
        foreach (var node in nodes)
            taskList.Add(Task.Run(() => node.Main(host, cts.Token), cts.Token)); // Nodes

        logger.LogInformation("Passing control to nodes");
        Task.WaitAll([.. taskList], cts.Token); ;
    }

    /// <summary>
    /// Like System.Console.ReadLine(), only with a mask.
    /// </summary>
    /// <param name="mask">a <c>char</c> representing your choice of console mask</param>
    /// <returns>the string the user typed in </returns>
    public static string ReadPassword(char mask)
    {
        const int ENTER = 13, BACKSP = 8, CTRLBACKSP = 127;
        int[] FILTERED = [0, 27, 9, 10];

        var pass = new Stack<char>();
        char chr = (char)0;

        while ((chr = Console.ReadKey(true).KeyChar) != ENTER)
        {
            if (chr == BACKSP)
            {
                if (pass.Count > 0)
                {
                    Console.Write("\b \b");
                    pass.Pop();
                }
            }
            else if (chr == CTRLBACKSP)
            {
                while (pass.Count > 0)
                {
                    Console.Write("\b \b");
                    pass.Pop();
                }
            }
            else if (FILTERED.Count(x => chr == x) > 0) { }
            else
            {
                pass.Push(chr);
                Console.Write(mask);
            }
        }

        Console.WriteLine();
        return new string(pass.Reverse().ToArray());
    }

    /// <summary>
    /// Like System.Console.ReadLine(), only with a mask.
    /// </summary>
    /// <returns>the string the user typed in </returns>
    public static string ReadPassword()
    {
        return ReadPassword('*');
    }
}