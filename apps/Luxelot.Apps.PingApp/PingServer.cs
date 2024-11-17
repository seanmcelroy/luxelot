using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Apps.PingApp.Messages;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.PingApp;

public class PingServer : IServerApp
{
    private IAppContext? appContext;

    public string Name => "ping";

    public bool InspectsForwarding => false;

    public void OnNodeInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
    }

    public bool CanHandle(Any message) => message.Is(Ping.Descriptor) || message.Is(Pong.Descriptor);

    public async Task<bool> HandleMessage(
        IRequestContext requestContext,
        Any message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(message);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        switch (message)
        {
            case Any any when any.Is(Ping.Descriptor):
                return await HandlePing(requestContext, any.Unpack<Ping>(), cancellationToken);
            case Any any when any.Is(Pong.Descriptor):
                return await HandlePong(requestContext, any.Unpack<Pong>(), cancellationToken);
            default:
                appContext?.Logger?.LogError("From {PeerShortName} ({RemoteEndPoint}): Unsupported forwarded message type {PayloadType}", requestContext.PeerShortName, requestContext.RemoteEndPoint, message.TypeUrl);
                return false;
        }

    }

    private async Task<bool> HandlePing(IRequestContext requestContext, Ping ping, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(ping);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        if (requestContext.RequestSourceThumbprint == null)
            throw new InvalidOperationException("Attempted to handle a ping from a peer for which we have no identity thumbprint profiled.");

        var pong = new Pong
        {
            Identifier = ping.Identifier,
            Sequence = ping.Sequence,
            Payload = ping.Payload
        };

        appContext.Logger?.LogDebug("Replying PONG {LocalEndPoint}->{RemoteEndPoint}", requestContext.LocalEndPoint, requestContext.RemoteEndPoint);
        return await appContext.SendMessage(requestContext.RequestSourceThumbprint, pong, cancellationToken);
    }

    private async Task<bool> HandlePong(IRequestContext requestContext, Pong pong, CancellationToken cancellationToken)
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        appContext.Logger?.LogInformation("PONG from {PeerShortName} ({RemoteEndPoint}): {Contents}", requestContext.PeerShortName, requestContext.RemoteEndPoint, $"id={pong.Identifier} seq={pong.Sequence}");
        await appContext.SendConsoleMessage($"{pong.CalculateSize()} bytes from {requestContext.RemoteEndPoint}: seq={pong.Sequence}", cancellationToken);
        return true;
    }
}