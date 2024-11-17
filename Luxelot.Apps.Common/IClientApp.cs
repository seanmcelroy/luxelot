namespace Luxelot.Apps.Common;

public interface IClientApp
{
    public string Name { get; }

    public void OnInitialize(IAppContext appContext);
}
