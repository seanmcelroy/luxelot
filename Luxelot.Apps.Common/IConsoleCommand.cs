namespace Luxelot.Apps.Common;

public interface IConsoleCommand
{
    public string Command { get; }

    public Task<bool> Invoke(IAppContext appContext, string[] words, CancellationToken cancellationToken);
}