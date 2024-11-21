using System.Collections.Immutable;
using System.Text;

namespace Luxelot.Apps.FserveApp;

public class ClientConnection
{
    public ImmutableArray<byte> SessionSharedKey { get; private set; }

    public ImmutableArray<byte>? Principal { get; set; }

    public string? PrincipalAsName { get => Principal == null ? null : Encoding.UTF8.GetString([.. Principal]); }

    public string CurrentWorkingDirectory { get; set; } = "/";

    public ClientConnection(ImmutableArray<byte> sessionSharedKey)
    {
        ArgumentNullException.ThrowIfNull(sessionSharedKey);

        SessionSharedKey = sessionSharedKey;
    }


}