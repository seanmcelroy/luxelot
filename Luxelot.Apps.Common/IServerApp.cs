using Google.Protobuf.WellKnownTypes;

namespace Luxelot.Apps.Common;

public interface IServerApp
{
    public void OnNodeInitialize(IAppContext appContext);

    public bool CanHandle(Any message);

    public Task<bool> HandleMessage(
        IRequestContext requestContext,
        Any message,
        CancellationToken cancellationToken);
}