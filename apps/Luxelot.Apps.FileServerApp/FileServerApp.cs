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

    private readonly ConcurrentDictionary<string, ClientConnection> ClientConnections = [];

    public bool CanHandle(Any message) =>
        message.Is(AuthChannelBegin.Descriptor)
        || message.Is(AuthChannelResponse.Descriptor)
        || message.Is(ClientFrame.Descriptor)
        || message.Is(ServerFrame.Descriptor); // All we need to handle is generic wrapped frame at the network level.

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
            case Any any when any.Is(AuthChannelResponse.Descriptor):
                {
                    if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp) || fileClientApp == null)
                    {
                        appContext.Logger?.LogError("Unable to get singleton for file client");
                        return false;
                    }
                    return await fileClientApp.HandleAuthChannelResponse(requestContext, any.Unpack<AuthChannelResponse>(), cancellationToken);
                }
            case Any any when any.Is(ClientFrame.Descriptor):
                {
                    // From a client
                    var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
                    if (!ClientConnections.TryGetValue(cacheKey, out ClientConnection? cc))
                    {
                        appContext.Logger?.LogDebug("AuthUserBegin received from {SourceThumbprint}, but not recorded as a client connection. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
                        return true;
                    }

                    var frame = any.Unpack<ClientFrame>();
                    var innerMessage = FrameUtils.UnwrapFrame(appContext, frame, [.. cc.SessionSharedKey]);
                    if (innerMessage is AuthUserBegin aub)
                        return await HandleAuthUserBegin(requestContext, aub, cancellationToken);
                    else
                    {
                        appContext?.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported client frame type: {FrameType}", requestContext.PeerShortName, requestContext.RemoteEndPoint, innerMessage.GetType().FullName);
                        return false;
                    }
                }

            case Any any when any.Is(ServerFrame.Descriptor):
                {
                    // From a server.
                    if (!appContext.TryGetSingleton(out FileClientApp? fileClientApp) || fileClientApp == null)
                    {
                        appContext.Logger?.LogError("Unable to get singleton for file client");
                        return false;
                    }

                    var frame = any.Unpack<ServerFrame>();
                    var innerMessage = FrameUtils.UnwrapFrame(appContext, frame, [.. fileClientApp.SessionSharedKey]);

                    if (innerMessage is AuthChannelResponse acr)
                        return await fileClientApp.HandleAuthChannelResponse(requestContext, acr, cancellationToken);
                    else if (innerMessage is Status sta)
                        return await fileClientApp.HandleStatus(requestContext, sta, cancellationToken);
                    else
                    {
                        appContext?.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported server frame type {PayloadType}", requestContext.PeerShortName, requestContext.RemoteEndPoint, innerMessage.GetType().FullName);
                        return false;
                    }
                }
            default:
                appContext?.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported forwarded message type {PayloadType}", requestContext.PeerShortName, requestContext.RemoteEndPoint, message.TypeUrl);
                return false;
        }
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

        var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
        appContext.Logger?.LogDebug("AuthChannelBegin from {SourceThumbprint} via {PeerShortName}", cacheKey, requestContext.PeerShortName);

        if (ClientConnections.ContainsKey(cacheKey))
        {
            appContext.Logger?.LogDebug("AuthChannelBegin received from {SourceThumbprint}, but already recorded as a client connection.", cacheKey);
            ClientConnections.Remove(cacheKey, out _);
        }

        var (encapsulatedKey, sessionSharedKey) = appContext.ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey([.. acb.SessionPubKey.ToByteArray()]);

        //appContext.Logger?.LogCritical("SERVER FSERV SESSION KEY: {SessionSharedKey}", DisplayUtils.BytesToHex(sessionSharedKey));

        var cc = new ClientConnection(sessionSharedKey);
        if (!ClientConnections.TryAdd(cacheKey, cc))
        {
            appContext.Logger?.LogWarning("AuthChannelBegin from {SourceThumbprint} discarded due to a concurrency issue.", cacheKey);
            return await appContext.SendMessage(requestContext.RequestSourceThumbprint,
                 new AuthChannelResponse
                 {
                     ProtVer = FS_PROTOCOL_VERSION,
                     Status = 400,
                     StatusMessage = "Initial exchange accepted, providing encapsulated key.",
                     CipherText = ByteString.CopyFrom(encapsulatedKey),
                     IdPubKey = ByteString.CopyFrom([.. appContext.IdentityKeyPublicBytes])
                 }, cancellationToken);
        };

        appContext.Logger?.LogInformation("AuthChannelBegin received from {SourceThumbprint}.  Sending continuation to establish secured channel.", cacheKey);

        return await appContext.SendMessage(
            requestContext.RequestSourceThumbprint,
            new AuthChannelResponse
            {
                ProtVer = FS_PROTOCOL_VERSION,
                Status = 200,
                StatusMessage = "Initial exchange accepted, providing encapsulated key.",
                CipherText = ByteString.CopyFrom(encapsulatedKey),
                IdPubKey = ByteString.CopyFrom([.. appContext.IdentityKeyPublicBytes])
            },
            cancellationToken);
    }

    private async Task<bool> HandleAuthUserBegin(IRequestContext requestContext, AuthUserBegin aub, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(aub);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
        if (!ClientConnections.TryGetValue(cacheKey, out ClientConnection? cc))
        {
            appContext.Logger?.LogDebug("AuthUserBegin received from {SourceThumbprint}, but not recorded as a client connection. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        appContext.Logger?.LogDebug("AuthUserBegin from {SourceThumbprint} via {PeerShortName}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), requestContext.PeerShortName);

        // TODO: User authentication.

        cc.Principal = [.. aub.Principal.ToByteArray()];

        var frame = FrameUtils.WrapServerFrame(
            appContext,
            new Status
            {
                Operation = Operation.Authentication,
                StatusCode = 200,
                StatusMessage = $"Welcome {cc.PrincipalAsName}!",
                ResultPayload = ByteString.Empty
            },
            cc.SessionSharedKey);

        return await appContext.SendMessage(requestContext.RequestSourceThumbprint, frame, cancellationToken);
    }
}