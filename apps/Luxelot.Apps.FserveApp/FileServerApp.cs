using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Luxelot.Apps.Common;
using Luxelot.Apps.FserveApp.Messages;
using Luxelot.Messages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Luxelot.Apps.FserveApp;

public class FserveApp : IServerApp
{
    public const uint FS_PROTOCOL_VERSION = 1;
    private const string ROOT = "::<<<ROOT>_>_>";

    private IAppContext? appContext;
    private IConfigurationSection? appConfig;
    private TreeNode? logicalRootNode;
    private readonly Dictionary<string, TreeNode> virtualRoots = [];

    public string Name => "fserve";

    public bool InspectsForwarding => false;

    private readonly ConcurrentDictionary<string, ClientConnection> ClientConnections = [];

    private static uint RecursiveCount(TreeNode t) => t.Children == null ? 0 : (t.Count + (uint)t.Children.Sum(t2 => RecursiveCount(t2.Value)));
    private static uint RecursiveSize(TreeNode t) => t.Children == null ? 0 : (t.Size + (uint)t.Children.Sum(t2 => RecursiveSize(t2.Value)));


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
                    else if (innerMessage is ListRequest lr)
                        return await HandleListRequest(requestContext, lr, cancellationToken);
                    else if (innerMessage is ChangeDirectoryRequest cdr)
                        return await HandleChangeDirectoryRequest(requestContext, cdr, cancellationToken);
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
                    else if (innerMessage is ListResponse lr)
                        return await fileClientApp.HandleListResponse(requestContext, lr, cancellationToken);
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

    public void OnNodeInitialize(IAppContext appContext, IConfigurationSection? appConfig)
    {
        ArgumentNullException.ThrowIfNull(appContext);
        this.appContext = appContext;
        this.appConfig = appConfig;

        _ = appContext.TryRegisterSingleton<FileClientApp>(() =>
        {
            var c = new FileClientApp();
            c.OnInitialize(appContext);
            return c;
        });

        logicalRootNode = BuildLogicalDirectoryTree();
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

        var (encapsulatedKey, sessionSharedKey) = appContext.ComputeSharedKeyAndEncapsulatedKeyFromKyberPublicKey([.. acb.SessionPubKey.ToByteArray()], appContext.Logger);

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

    private TreeNode BuildLogicalDirectoryTree()
    {
        if (appConfig == null)
            return TreeNode.EmptyRoot;

        appContext?.Logger?.LogInformation("Reading mounts configuration");


        var mountsConfig = appConfig.Get<Config.MountsConfig>();
        if (mountsConfig == null)
        {
            appContext?.Logger?.LogError("Unable to get Mounts configuration from settings.");
            return TreeNode.EmptyRoot;
        }

        // Depth first searching
        virtualRoots.Clear();
        Dictionary<string, TreeNode> logicalMounts = [];
        foreach (var mount in mountsConfig.Mounts)
        {
            var virtualMountPoint = mount.Key;

            if (string.IsNullOrWhiteSpace(virtualMountPoint))
            {
                appContext?.Logger?.LogWarning("Empty virtual mount point is not allowed.  Mount points must be more than one character and being with a forward slash. Skipping.");
                continue;
            }

            if (virtualMountPoint.Length == 1 && virtualMountPoint[0] == '/')
            {
                appContext?.Logger?.LogWarning("Virtual mount point '/' is not allowed.  Mount points must be more than one character and being with a forward slash. Skipping.");
                continue;
            }

            if (virtualMountPoint[0] != '/')
            {
                appContext?.Logger?.LogWarning("Virtual mount point '{VirtualPath}' is not allowed.  Mount points must be more than one character and being with a forward slash. Skipping.", virtualMountPoint);
                continue;
            }

            var actualPath = mount.Value.RealPath;
            if (actualPath.EndsWith(Path.DirectorySeparatorChar))
                actualPath = actualPath[..^1];

            //            else
            //                nodes.Add(realCurrent, new TreeNode { Name = mountPoint[1..], Children = null, Count = 0, DescendentCount = 0, Size = uint.MaxValue, DescendentSize = 0, LastModified = null });


            logicalMounts.Add(actualPath, BuildTreeNode(virtualMountPoint, actualPath, actualPath, mount.Value.RecursiveDepth, virtualRoots));
        }

        var logicalMountRoot = new TreeNode
        {
            RelativeName = "/",
            RelativePath = "/",
            AbsolutePath = string.Empty,
            Children = logicalMounts.ToImmutableDictionary(),
            Count = (uint)logicalMounts.Count,
            DescendentCount = 0, // Set following this statement
            Size = uint.MaxValue,
            DescendentSize = 0, // Set following this statement
            LastModified = null,
        };
        logicalMountRoot.DescendentCount = RecursiveCount(logicalMountRoot);
        logicalMountRoot.DescendentSize = RecursiveSize(logicalMountRoot);

        virtualRoots.Add("/", logicalMountRoot);

        return logicalMountRoot;
    }

    private static TreeNode BuildTreeNode(
        string mountPoint,
        string realRoot,
        string realCurrent,
        int recursiveDepth,
        Dictionary<string, TreeNode> virtualRoot)
    {
        ArgumentNullException.ThrowIfNull(realRoot);
        ArgumentNullException.ThrowIfNull(realCurrent);
        if (!Directory.Exists(realRoot))
            throw new DirectoryNotFoundException(realRoot);
        if (!Directory.Exists(realCurrent))
            throw new DirectoryNotFoundException(realCurrent);

        Dictionary<string, TreeNode> nodes = [];
        uint vcount = 1;

        var relativeDirName = Path.GetRelativePath(realRoot, realCurrent);
        var relativeMountPath = Path.Combine(mountPoint, relativeDirName);

        try
        {

            // This . add if not root, or base name if root
            if (relativeDirName == ".")
            {
                nodes.Add(realCurrent, new TreeNode { RelativeName = ".", RelativePath = relativeMountPath, AbsolutePath = realCurrent, Children = null, Count = 0, DescendentCount = 0, Size = uint.MaxValue, DescendentSize = 0, LastModified = null });
            }

            // Parent ..
            if (string.Compare(realRoot, realCurrent, StringComparison.OrdinalIgnoreCase) != 0)
            {
                var parent = Directory.GetParent(realCurrent);
                if (parent != null)
                {
                    var relParentPath = Path.GetRelativePath(realRoot, parent.FullName);

                    var relMountParentPath = (string.CompareOrdinal(relParentPath, ".") == 0)
                        ? mountPoint
                        : Path.Combine(mountPoint, relParentPath);

                    nodes.Add(parent.FullName, new TreeNode { RelativeName = "..", RelativePath = relMountParentPath, AbsolutePath = parent.FullName, Children = null, Count = 0, DescendentCount = 0, Size = uint.MaxValue, DescendentSize = 0, LastModified = null });
                    vcount++;
                }
            }
            else
            {
                nodes.Add(ROOT, new TreeNode { RelativeName = "..", RelativePath = ROOT, AbsolutePath = realRoot, Children = null, Count = 0, DescendentCount = 0, Size = uint.MaxValue, DescendentSize = 0, LastModified = null });
                vcount++;
            }

            // Subdirectories
            if (recursiveDepth > 0)
            {
                try
                {
                    foreach (var subdir in Directory.GetDirectories(realCurrent))
                    {
                        nodes.Add(subdir, BuildTreeNode(mountPoint, realRoot, subdir, recursiveDepth - 1, virtualRoot));
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    // Swallow.  Some types of *nix files behave this way.
                }
            }

            // Files
            {
                try
                {
                    foreach (var file in Directory.GetFiles(realCurrent))
                    {
                        var relFilePath = Path.GetRelativePath(realRoot, file);
                        var relFileName = Path.GetFileName(relFilePath);
                        var fi = new FileInfo(file);
                        var size = (uint)fi.Length;
                        nodes.Add(file, new TreeNode
                        {
                            RelativeName = relFileName,
                            RelativePath = relFilePath,
                            AbsolutePath = fi.FullName,
                            Children = null,
                            Count = 0,
                            DescendentCount = 0,
                            Size = size,
                            DescendentSize = size,
                            LastModified = fi.LastWriteTimeUtc,
                        });
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    // Swallow.  Some types of *nix files behave this way.
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Swallow.
        }


        var relName = (string.CompareOrdinal(relativeDirName, ".") == 0)
            ? mountPoint[1..]
            : relativeDirName;

        var relMountPath = (string.CompareOrdinal(relativeDirName, ".") == 0)
            ? mountPoint
            : relativeMountPath;

        var ret = new TreeNode
        {
            RelativeName = relName,
            RelativePath = relMountPath,
            AbsolutePath = realCurrent,
            Children = nodes.ToImmutableDictionary(),
            Count = (uint)nodes.Count - vcount, // Don't count . and ..
            DescendentCount = 0, // Set following this statement
            Size = uint.MaxValue, // Directories have no inherent size
            DescendentSize = 0, // Set following this statement
            LastModified = null,
        };
        virtualRoot.Add(relMountPath, ret);

        ret.DescendentCount = RecursiveCount(ret);
        ret.DescendentSize = RecursiveSize(ret);
        return ret;

    }

    private async Task<bool> HandleListRequest(IRequestContext requestContext, ListRequest lr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(lr);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
        if (!ClientConnections.TryGetValue(cacheKey, out ClientConnection? cc))
        {
            appContext.Logger?.LogDebug("ListRequest received from {SourceThumbprint}, but not recorded as a client connection. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        appContext.Logger?.LogDebug("ListRequest from {SourceThumbprint} via {PeerShortName}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), requestContext.PeerShortName);

        // TODO: Search pattern visitor pattern

        // Build tree if it hasn't already been built.
        logicalRootNode ??= BuildLogicalDirectoryTree();

        var targetDir = string.IsNullOrWhiteSpace(lr.Directory) ? cc.CurrentWorkingDirectory : lr.Directory;

        if (!virtualRoots.TryGetValue(targetDir, out TreeNode? virt))
        {
            return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                appContext,
                new ListResponse
                {
                    StatusCode = 404,
                    StatusMessage = "Directory not found",
                    Directory = targetDir,
                    Pattern = lr.Pattern
                },
                cc.SessionSharedKey), cancellationToken);
        }

        var resp = new ListResponse
        {
            StatusCode = 200,
            StatusMessage = "Results returned",
            Directory = targetDir,
            Pattern = lr.Pattern,
        };
        if (virt.Children != null)
        {
            resp.Results.AddRange(virt.Children.OrderBy(c => c.Value.RelativeName).Select(c => new Result
            {
                Name = c.Value.RelativeName,
                Size = c.Value.Size,
                Modified = c.Value.LastModified == null ? null : Timestamp.FromDateTimeOffset(c.Value.LastModified.Value)
            }));
        }

        return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
            appContext,
            resp,
            cc.SessionSharedKey), cancellationToken);
    }

    private async Task<bool> HandleChangeDirectoryRequest(IRequestContext requestContext, ChangeDirectoryRequest cdr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(cdr);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
        if (!ClientConnections.TryGetValue(cacheKey, out ClientConnection? cc))
        {
            appContext.Logger?.LogDebug("ChangeDirectoryRequest received from {SourceThumbprint}, but not recorded as a client connection. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        appContext.Logger?.LogDebug("ChangeDirectoryRequest from {SourceThumbprint} via {PeerShortName}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), requestContext.PeerShortName);

        // Build tree if it hasn't already been built.
        logicalRootNode ??= BuildLogicalDirectoryTree();

        if (cdr.Directory.StartsWith('/'))
        {
            // Absolute
            if (!virtualRoots.TryGetValue(cdr.Directory, out TreeNode? virt))
            {
                return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                    appContext,
                    new Status
                    {
                        Operation = Operation.Cd,
                        StatusCode = 404,
                        StatusMessage = "Directory not found",
                        ResultPayload = ByteString.CopyFrom(Encoding.UTF8.GetBytes(cdr.Directory))
                    },
                    cc.SessionSharedKey), cancellationToken);
            }

            cc.CurrentWorkingDirectory = cdr.Directory;
        }
        else
        {
            if (!virtualRoots.TryGetValue(cc.CurrentWorkingDirectory, out TreeNode? virtCwd))
            {
                return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                    appContext,
                    new Status
                    {
                        Operation = Operation.Cd,
                        StatusCode = 404,
                        StatusMessage = "Current working directory not found",
                        ResultPayload = ByteString.CopyFrom(Encoding.UTF8.GetBytes(cc.CurrentWorkingDirectory))
                    },
                    cc.SessionSharedKey), cancellationToken);
            }

            var virtChild = virtCwd.Children?.FirstOrDefault(c => string.Compare(c.Value.RelativeName, cdr.Directory, StringComparison.Ordinal) == 0);
            if (virtChild == null || virtChild.Equals(default(KeyValuePair<string, TreeNode>)))
            {
                return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                    appContext,
                    new Status
                    {
                        Operation = Operation.Cd,
                        StatusCode = 404,
                        StatusMessage = "Directory not found",
                        ResultPayload = ByteString.CopyFrom(Encoding.UTF8.GetBytes(cdr.Directory))
                    },
                    cc.SessionSharedKey), cancellationToken);
            }

            if (string.Compare(virtChild.Value.Value.RelativePath, ROOT, StringComparison.Ordinal) == 0)
                cc.CurrentWorkingDirectory = "/";
            else
                cc.CurrentWorkingDirectory = virtChild.Value.Value.RelativePath;
        }

        var resp = new Status
        {
            Operation = Operation.Cd,
            StatusCode = 200,
            StatusMessage = cc.CurrentWorkingDirectory,
        };

        return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
            appContext,
            resp,
            cc.SessionSharedKey), cancellationToken);
    }
}