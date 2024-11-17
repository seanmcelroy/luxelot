using System.Collections.Immutable;
using Luxelot.Apps.Common;

namespace Luxelot.Apps.FileServerApp;

/// <summary>
/// This is a simple fserve client app which does not provide for multiple sessions or downloads
/// </summary>
public class FileClientApp : IClientApp
{
    private IAppContext? appContext;

    public ImmutableArray<byte>? SessionPublicKey { get; private set; }
    private ImmutableArray<byte>? SessionPrivateKey { get; set; }
    public ImmutableArray<byte>? SessionSharedKey { get; private set; }

    public string Name => "Fserve Client";

    public void OnInitialize(IAppContext appContext)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;

        Reset();
    }

    public void Reset()
    {
        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var (publicKeyBytes, privateKeyBytes) = appContext.GenerateKyberKeyPair();
        SessionPublicKey = publicKeyBytes;
        SessionPrivateKey = privateKeyBytes;
        SessionSharedKey = null;// Computed after AuthChannelResponse received
    }
}