using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;

namespace Luxelot.Apps.FileServerApp;

public class FileServerApp : IServerApp
{
    private IAppContext? appContext;

    public string Name => "fserve";

    public bool InspectsForwarding => false;

    public bool CanHandle(Any message)
    {
        throw new NotImplementedException();
    }

    public Task<bool> HandleMessage(IRequestContext requestContext, Any message, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public void OnNodeInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }
}