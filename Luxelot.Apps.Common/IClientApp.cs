namespace Luxelot.Apps.Common;

public interface IClientApp
{
    public string Name { get; }

    public string InteractiveCommand { get; }

    public void OnInitialize(IAppContext appContext);

    public Task OnActivate(CancellationToken cancellationToken);

    public Task<bool> HandleUserInput(string input, CancellationToken cancellationToken);
}
