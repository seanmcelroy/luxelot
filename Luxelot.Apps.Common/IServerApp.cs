using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Configuration;

namespace Luxelot.Apps.Common;

public interface IServerApp
{
    public string Name { get; }

    public bool InspectsForwarding { get; }

    public void OnNodeInitialize(INode node, IAppContext appContext, IConfigurationSection? appConfig);

    public bool CanHandle(Any message);

    public Task<bool> HandleMessage(
        IRequestContext requestContext,

        Any message,
        CancellationToken cancellationToken);
}