using System.Data;
using System.Reflection;
using System.Text;
using Luxelot.Apps.Common;
using Luxelot.Apps.DhtApp.Messages;
using Microsoft.Extensions.Logging;
using static Luxelot.Apps.Common.RegexUtils;

namespace Luxelot.Apps.DhtApp;

/// <summary>
/// This is a user interactive DHT client app which does not provide for multiple sessions or downloads.
/// 
/// An instance of this class ia a 'client' to another node's DHT server.
/// </summary>
public class DhtClientApp : IClientApp
{
    internal const string CLIENT_APP_NAME = "DHT Client";

    private IAppContext? appContext;

    public string Name => CLIENT_APP_NAME;

    public string? InteractiveCommand => "dht";

    public List<IConsoleCommand> Commands { get; init; } = [];

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;

        // Load Console Commands
        var consoleCommandTypes = Assembly.GetExecutingAssembly().GetTypes().Where(t => t.IsClass && t.GetInterfaces().Any(t => string.CompareOrdinal(t.FullName, typeof(IConsoleCommand).FullName) == 0)).ToArray();
        foreach (var consoleCommandType in consoleCommandTypes)
        {
            var objApp = Activator.CreateInstance(consoleCommandType, true);
#pragma warning disable IDE0019 // Use pattern matching
            var consoleCommand = objApp as IConsoleCommand;
#pragma warning restore IDE0019 // Use pattern matching
            if (consoleCommand == null)
            {
                appContext.Logger?.LogError("Unable to load console command {TypeName}", consoleCommandType.FullName);
                continue;
            }

            Commands.Add(consoleCommand);
            consoleCommand.OnInitialize(appContext);
            appContext.Logger?.LogInformation("Loaded console command '{CommandName}' ({TypeName})", consoleCommand.InteractiveCommand, consoleCommandType.FullName);
        }
    }

    public async Task OnActivate(CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        await appContext.SendConsoleMessage($"{Name} {version}", cancellationToken);
    }

    public async Task<HandleUserInputResult> HandleUserInput(string input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(input);

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        if (!appContext.TryGetSingleton(out DhtClientApp? ca)
            || ca == null)
        {
            appContext.Logger?.LogError("Unable to get singleton for DHT client");
            return new HandleUserInputResult
            {
                Success = false,
                ErrorMessage = "Internal error.",
                Command = null
            };
        }

        var sb = new StringBuilder();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                sb.AppendLine($"\r\n{InteractiveCommand}> COMMAND LIST");
                var built_in_cmds = new string[] { "version", "exit" };
                var cmd_len = built_in_cmds.Union(ca.Commands.Select(c => c.InteractiveCommand)).Max(c => c.Length);
                var loaded_cmds = ca.Commands.Select(c => $"{c.InteractiveCommand.PadRight(cmd_len)}: {c.ShortHelp}");
                sb.AppendLine($"{InteractiveCommand}> {built_in_cmds.Union(loaded_cmds).Order().Aggregate((c, n) => $"{c}\r\n{InteractiveCommand}> {n}")}");
                sb.AppendLine($"{InteractiveCommand}> END OF COMMAND LIST").AppendLine();
                await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
                return new HandleUserInputResult
                {
                    Success = true,
                    ErrorMessage = null,
                    Command = null
                };

            case "version":
                var version = Assembly.GetExecutingAssembly().GetName().Version;
                await appContext.SendConsoleMessage($"{Name} app v{version}", cancellationToken);
                return new HandleUserInputResult
                {
                    Success = true,
                    ErrorMessage = null,
                    Command = null
                };

            default:
                // Maybe it's a command this client app loaded?
                var appCommand = ca.Commands.FirstOrDefault(cc =>
                    string.Compare(cc.InteractiveCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0
                    || cc.InteractiveAliases.Any(a => string.Compare(a, command, StringComparison.InvariantCultureIgnoreCase) == 0));

                if (appCommand != null)
                {
                    var (success, errorMessage) = await appCommand.Invoke(words, cancellationToken);
                    return new HandleUserInputResult
                    {
                        Success = success,
                        ErrorMessage = errorMessage,
                        Command = appCommand
                    };
                }

                return new HandleUserInputResult
                {
                    Success = false,
                    ErrorMessage = $"Unknown command '{command.Trim()}'. Type 'exit' to exit this app.",
                    Command = null
                };
        }
    }

    public Task OnDeactivate(CancellationToken cancellationToken) => Task.CompletedTask;
}