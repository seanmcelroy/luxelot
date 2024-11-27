using System.Reflection;
using System.Text;
using Luxelot.Apps.Common;
using Microsoft.Extensions.Logging;
using static Luxelot.Apps.Common.RegexUtils;

namespace Luxelot.Apps.PingApp;

/// <summary>
/// This is a simple fserve client app which does not provide for multiple sessions or downloads.
/// 
/// An instance of this class ia a 'client' to another node's fserve.
/// </summary>
public class PingClientApp : IClientApp
{
    private IAppContext? appContext;
    public List<IConsoleCommand> Commands { get; init; } = [];

    public string Name => "Ping Client";

    public string? InteractiveCommand => null;

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
            appContext.Logger?.LogInformation("Loaded console command '{CommandName}' ({TypeName})", consoleCommand.FullCommand, consoleCommandType.FullName);
        }
    }

    public async Task OnActivate(CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        await appContext.SendConsoleMessage($"{Name} {version}", cancellationToken);
    }

    public async Task<(bool handled, bool success)> TryInvokeCommand(string command, string[] words, CancellationToken cancellationToken)
    {
        var appCommand = Commands.FirstOrDefault(cc => string.Compare(cc.FullCommand, command, StringComparison.InvariantCultureIgnoreCase) == 0);
        if (appCommand == null)
            return (false, false);
        var success = await appCommand.Invoke(words, cancellationToken);
        return (true, success);
    }

    public async Task<bool> HandleUserInput(string input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        ArgumentNullException.ThrowIfNull(input);

        var words = QuotedWordArrayRegex().Split(input).Where(s => s.Length > 0).ToArray();
        var command = words.First();

        var sb = new StringBuilder();

        switch (command.ToLowerInvariant())
        {
            case "?":
            case "help":
                sb.AppendLine($"{Environment.NewLine}{InteractiveCommand}> COMMAND LIST");
                var built_in_cmds = new string[] { "version", "exit", "ping" };
                sb.AppendLine($"{InteractiveCommand}> {built_in_cmds.Order().Aggregate((c, n) => $"{c}{Environment.NewLine}{InteractiveCommand}> {n}")}");
                sb.AppendLine($"{InteractiveCommand}> END OF COMMAND LIST{Environment.NewLine}");
                await appContext.SendConsoleMessage(sb.ToString(), cancellationToken);
                return true;

            case "version":
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                await appContext.SendConsoleMessage($"{Name} v{version}", cancellationToken);
                return true;

            case "ping":
                var ping = new PingCommand();
                ping.OnInitialize(appContext);
                return await ping.Invoke(words, cancellationToken);

            default:
                await appContext.SendConsoleMessage($"{InteractiveCommand}> Unknown command '{command.Trim()}'. Type 'exit' to exit this app.", cancellationToken);
                return false;
        }
    }

    public Task OnDeactivate(CancellationToken cancellationToken) => Task.CompletedTask;
}