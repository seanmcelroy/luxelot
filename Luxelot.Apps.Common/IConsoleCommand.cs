namespace Luxelot.Apps.Common;

public interface IConsoleCommand
{
    public string Command { get; }

    public void OnInitialize(IAppContext appContext);

    public Task<bool> Invoke(string[] words, CancellationToken cancellationToken);
}