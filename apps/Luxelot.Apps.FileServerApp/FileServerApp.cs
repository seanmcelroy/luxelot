using System.Collections.Concurrent;
using System.Collections.Immutable;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Apps.FileServerApp.Messages;
using Luxelot.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FileServerApp;

public class FileServerApp : IServerApp
{
    public const uint FS_PROTOCOL_VERSION = 1;

    private IAppContext? appContext;

    public string Name => "fserve";

    public bool InspectsForwarding => false;

    private readonly ConcurrentDictionary<ImmutableArray<byte>, ClientConnection> ClientConnections = [];

    public bool CanHandle(Any message) => 
        message.Is(AuthChannelBegin.Descriptor)
        || message.Is(AuthChannelResponse.Descriptor);

    public async Task<bool> HandleMessage(IRequestContext requestContext, Any message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(message);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        switch (message)
        {
            case Any any when any.Is(AuthChannelBegin.Descriptor):
                return await HandleAuthChannelBegin(requestContext, any.Unpack<AuthChannelBegin>(), cancellationToken);
            default:
                appContext?.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported forwarded message type {PayloadType}", requestContext.PeerShortName, requestContext.RemoteEndPoint, message.TypeUrl);
                return false;
        }

        throw new NotImplementedException();
    }

    public void OnNodeInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;

        _ = appContext.TryRegisterSingleton<FileClientApp>(() =>
        {
            var c = new FileClientApp();
            c.OnInitialize(appContext);
            return c;
        });
    }

    private async Task<bool> HandleAuthChannelBegin(IRequestContext requestContext, AuthChannelBegin acb, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(acb);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        appContext.Logger?.LogDebug("AuthChannelBegin from {SourceThumbprint} via {PeerShortName}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), requestContext.PeerShortName);

        if (ClientConnections.ContainsKey(requestContext.RequestSourceThumbprint)) {
            appContext.Logger?.LogDebug("AuthChannelBegin received from {SourceThumbprint}, but already recorded as a client connection.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            ClientConnections.Remove(requestContext.RequestSourceThumbprint, out _);
        }

        var (encapsulatedKey, sessionSharedKey) = appContext.ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey([.. acb.SessionPubKey.ToByteArray()]);

        var authChannelResponse = new AuthChannelResponse{
            ProtVer = FS_PROTOCOL_VERSION,
            Status = 200,
            StatusMessage = "Initial exchange accepted, providing encapsulated key.",
            CipherText = ByteString.CopyFrom(encapsulatedKey),
            IdPubKey = ByteString.CopyFrom([.. appContext.IdentityKeyPublicBytes])
        };

        var success = await appContext.SendMessage(requestContext.RequestSourceThumbprint, authChannelResponse, cancellationToken);
        return success;
    }
}