using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Apps.DhtApp.Messages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.DhtApp;

public class DhtServerApp : IServerApp
{
    private IAppContext? appContext;
    private IConfigurationSection? appConfig;

    public string Name => "dht";

    public bool InspectsForwarding => false;

    internal readonly Dictionary<DhtTableType, KademliaDistributedHashTable> Tables = [];

    public bool CanHandle(Any message) =>
        message.Is(DhtFindRequest.Descriptor)
        || message.Is(DhtFindResponse.Descriptor); // All we need to handle is generic wrapped frame at the network level.

    public Task<bool> HandleMessage(IRequestContext requestContext, Any message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(message);

        using var scope = appContext?.Logger?.BeginScope(nameof(HandleMessage));

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        switch (message)
        {
            case Any any when any.Is(DhtFindRequest.Descriptor):
                throw new NotImplementedException();
            //return await HandleAuthChannelBegin(requestContext, any.Unpack<AuthChannelBegin>(), cancellationToken);
            case Any any when any.Is(DhtFindResponse.Descriptor):
                throw new NotImplementedException();

            default:
                appContext?.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported forwarded message type {PayloadType}", requestContext.PeerShortName, requestContext.RemoteEndPoint, message.TypeUrl);
                return Task.FromResult(false);
        }
    }

    public void OnNodeInitialize(INode node, IAppContext appContext, IConfigurationSection? appConfig)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
        this.appConfig = appConfig;

        foreach (var v in System.Enum.GetValues<DhtTableType>())
        {
            Tables.Add(v, new KademliaDistributedHashTable(appContext.IdentityKeyPublicThumbprint));
        }

        node.PeerConnected += (sender, args) =>
        {
            // Don't add loopback
            if (args.PublicKey.All(b => b == 0x00))
                return;

            Tables[DhtTableType.Node].InsertBucketValue(
                appContext.IdentityKeyPublicThumbprint, // Used to calculate distance metric
                args.Thumbprint,
                new NodeEntry { 
                    RemoteEndpoint = args.RemoteEndpoint, 
                    IdentityPublicKey = args.PublicKey,
                    IdentityThumbprint = args.Thumbprint
                },
                appContext.Logger);
        };
    }
}