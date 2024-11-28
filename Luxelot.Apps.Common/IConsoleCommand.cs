namespace Luxelot.Apps.Common;

public interface IConsoleCommand
{
    public string FullCommand { get; }

    public string InteractiveCommand { get; }

    public string[] InteractiveAliases { get; }

    public string ShortHelp { get; }

    public string Usage { get; }

    public string Example { get; }

    public void OnInitialize(IAppContext appContext);

    public Task<(bool success, string? errorMessage)> Invoke(string[] words, CancellationToken cancellationToken);
}