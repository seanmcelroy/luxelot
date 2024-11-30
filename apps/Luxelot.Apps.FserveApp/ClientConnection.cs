using System.Collections.Immutable;
using System.Text;

namespace Luxelot.Apps.FserveApp;

public class ClientConnection(ImmutableArray<byte> sessionSharedKey)
{
    public ImmutableArray<byte> SessionSharedKey { get; private set; } = sessionSharedKey;

    public ImmutableArray<byte>? Principal { get; set; }

    public string? PrincipalAsName { get => Principal == null ? null : Encoding.UTF8.GetString(Principal.Value.AsSpan()); }

    public string CurrentWorkingDirectory { get; set; } = "/";
}