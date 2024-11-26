using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Security.Cryptography;
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

    /// <summary>
    /// Chunks waiting to be downloaded, keyed by the download 'ticket' and the chunks as the key.
    /// </summary>
    private readonly ConcurrentDictionary<string, (ChunkInfo chunkInfo, string chunkFileName)[]> ServerChunks = [];

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

        using var scope = appContext?.Logger?.BeginScope("HandleMessage");

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
                    else if (innerMessage is ChangeDirectory cdr)
                        return await HandleChangeDirectoryRequest(requestContext, cdr, cancellationToken);
                    else if (innerMessage is PrepareDownload pd)
                        return await HandlePrepareDownload(requestContext, pd, cancellationToken);
                    else if (innerMessage is ChunkRequest cr)
                        return await HandleGetChunk(requestContext, cr, cancellationToken);
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

                    if (fileClientApp.SessionSharedKey == null)
                    {
                        appContext.Logger?.LogError("Unable to unwrap received server frame, no active session");
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
                    else if (innerMessage is DownloadReady dr)
                        return await fileClientApp.HandleDownloadReady(requestContext, dr, cancellationToken);
                    else if (innerMessage is ChunkResponse cr)
                        return await fileClientApp.HandleChunkResponse(requestContext, cr, cancellationToken);
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

        // Clear old tickets
        var tempDir = Path.GetTempPath();
        foreach (var dir in Directory.GetDirectories(tempDir, "luxelot-fs-*"))
        {
            try
            {
                Directory.Delete(dir, true);
                appContext.Logger?.LogDebug("Deleted old ticket directory: {Directory}", dir);
            }
            catch (Exception ex)
            {
                appContext.Logger?.LogError(ex, "Unable to clear old ticket directory: {Directory}", dir);
            }
        }

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
        if (mountsConfig == null || mountsConfig.Mounts == null)
        {
            appContext?.Logger?.LogError("Unable to get Mounts configuration from settings.");
            return TreeNode.EmptyRoot;
        }

        if (mountsConfig.Mounts.Count == 0)
        {
            appContext?.Logger?.LogError("No Mounts specified in the configuration settings.");
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

            if (!Directory.Exists(actualPath)) {
                appContext?.Logger?.LogWarning("Logical mount path '{LogicalPath}' does not exist.  Skipping.", actualPath);
                continue;
            }

            var mountRoot = BuildTreeNode(virtualMountPoint, actualPath, actualPath, actualPath, mount.Value.RecursiveDepth, virtualRoots, mountsConfig.HideEmptyDirectories);
            if (mountRoot != null)
                logicalMounts.Add(actualPath, mountRoot);
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

    private TreeNode? BuildTreeNode(
        string mountPoint,
        string realRoot,
        string realParent,
        string realCurrent,
        int recursiveDepth,
        Dictionary<string, TreeNode> virtualRoot,
        bool hideEmptyDirectories)
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
            var subdirCount = 0;
            if (recursiveDepth > 0)
            {
                try
                {
                    foreach (var subdir in Directory.GetDirectories(realCurrent))
                    {
                        var subdirNode = BuildTreeNode(mountPoint, realRoot, relativeDirName, subdir, recursiveDepth - 1, virtualRoot, hideEmptyDirectories);
                        if (subdirNode != null)
                        {
                            subdirCount++;
                            nodes.Add(subdir, subdirNode);
                        }
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    // Swallow.  Some types of *nix files behave this way.
                }
            }

            // Files
            var fileCount = 0;
            {
                try
                {
                    foreach (var file in Directory.GetFiles(realCurrent))
                    {
                        fileCount++;
                        var relFilePath = Path.Combine(mountPoint, Path.GetRelativePath(realRoot, file));
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

            if (subdirCount == 0 && fileCount == 0 && hideEmptyDirectories)
                return null;
        }
        catch (UnauthorizedAccessException)
        {
            // Swallow.
        }

        var relName = (string.CompareOrdinal(relativeDirName, ".") == 0)
            ? mountPoint[1..]
            : relativeDirName[(relativeDirName.LastIndexOf('/') + 1)..]; //relativeDirName;

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

    private async Task<bool> HandleChangeDirectoryRequest(IRequestContext requestContext, ChangeDirectory cdr, CancellationToken cancellationToken)
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

    private async Task<bool> HandlePrepareDownload(IRequestContext requestContext, PrepareDownload pd, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(pd);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
        if (!ClientConnections.TryGetValue(cacheKey, out ClientConnection? cc))
        {
            appContext.Logger?.LogDebug("PrepareDownload received from {SourceThumbprint}, but not recorded as a client connection. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        appContext.Logger?.LogDebug("PrepareDownload from {SourceThumbprint} via {PeerShortName}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), requestContext.PeerShortName);

        // Build tree if it hasn't already been built.
        logicalRootNode ??= BuildLogicalDirectoryTree();

        TreeNode fileTreeNode;

        if (pd.File.StartsWith('/'))
        {
            // Absolute
            var fileDir = Path.GetDirectoryName(pd.File);
            if (fileDir == null
                || !virtualRoots.TryGetValue(fileDir, out TreeNode? virtFolder)
                || virtFolder.Children == null
                || !virtFolder.Children.TryGetValue(Path.Combine(virtFolder.AbsolutePath, Path.GetFileName(pd.File)), out TreeNode? virtFile)
                )
            {
                return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                    appContext,
                    new Status
                    {
                        Operation = Operation.PrepareDownload,
                        StatusCode = 404,
                        StatusMessage = "File not found",
                        ResultPayload = ByteString.CopyFrom(Encoding.UTF8.GetBytes(pd.File))
                    },
                    cc.SessionSharedKey), cancellationToken);
            }

            fileTreeNode = virtFile;
        }
        else
        {
            if (!virtualRoots.TryGetValue(cc.CurrentWorkingDirectory, out TreeNode? virtCwd))
            {
                return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                    appContext,
                    new Status
                    {
                        Operation = Operation.PrepareDownload,
                        StatusCode = 404,
                        StatusMessage = "Current working directory not found",
                        ResultPayload = ByteString.CopyFrom(Encoding.UTF8.GetBytes(cc.CurrentWorkingDirectory))
                    },
                    cc.SessionSharedKey), cancellationToken);
            }

            var virtChild = virtCwd.Children?.FirstOrDefault(c => string.Compare(c.Value.RelativeName, pd.File, StringComparison.Ordinal) == 0);
            if (virtChild == null
                || virtChild.Equals(default(KeyValuePair<string, TreeNode>))
                || virtChild.Value.Value.Children != null // Directory
                )
            {
                return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                    appContext,
                    new Status
                    {
                        Operation = Operation.PrepareDownload,
                        StatusCode = 404,
                        StatusMessage = "File not found",
                        ResultPayload = ByteString.CopyFrom(Encoding.UTF8.GetBytes(pd.File))
                    },
                    cc.SessionSharedKey), cancellationToken);
            }

            fileTreeNode = virtChild.Value.Value;
        }

        var fi = new FileInfo(fileTreeNode.AbsolutePath);
        var ticket = $"luxelot-fs-{requestContext.PeerShortName}-{Guid.NewGuid()}";
        var fileHash = await SHA256.HashDataAsync(File.Open(fileTreeNode.AbsolutePath, FileMode.Open, FileAccess.Read, FileShare.Read), cancellationToken);

        var tempDir = Path.GetTempPath();
        var ticketDir = Path.Combine(tempDir, ticket);
        var ticketDirectoryInfo = Directory.CreateDirectory(ticketDir);

        // Carve up into 1MB chunks
        using var fsFile = new FileStream(fi.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var buff = new BufferedStream(fsFile);
        using var brFile = new BinaryReader(buff);
        byte[] chunkBuffer = new byte[1024 * 1024];

        var localChunks = new List<(ChunkInfo chunkInfo, string chunkFileName)>();
        var count = 0;
        do
        {
            count++;
            var chunkBytes = brFile.Read(chunkBuffer, 0, chunkBuffer.Length);
            if (chunkBytes == 0)
                break;
            var chunkHash = SHA256.HashData(chunkBuffer.AsSpan(0, chunkBytes)).ToImmutableArray();

            var chunkFilename = Path.GetTempFileName();
            var relocatedChunkFilename = Path.Combine(ticketDir, Path.GetFileName(chunkFilename));
            File.Move(chunkFilename, Path.Combine(ticketDir, chunkFilename));
            chunkFilename = relocatedChunkFilename;

            using var fsChunk = new FileStream(chunkFilename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
            using var bwChunk = new BinaryWriter(fsChunk);
            bwChunk.Write(chunkBuffer.AsSpan(0, chunkBytes)); // No additional encryption since we're going over our E2EE.

            localChunks.Add((
                new ChunkInfo
                {
                    ServerThumbprint = appContext.IdentityKeyPublicThumbprint, // It's always myself.
                    FileName = fileTreeNode.RelativePath,
                    DownloadTicket = ticket,
                    FileSize = fileTreeNode.Size,
                    FileHash = [.. fileHash],
                    ChunkSequence = (uint)count,
                    ChunkSize = (uint)chunkBytes,
                    ChunkHash = chunkHash
                },
                chunkFilename));
        } while (!cancellationToken.IsCancellationRequested);

        var resp = new DownloadReady
        {
            File = fileTreeNode.RelativePath,
            Ticket = ticket,
            Size = fileTreeNode.Size,
            Hash = ByteString.CopyFrom(fileHash),
            IsEncrypted = true,
            IsDirectUdp = false,
            ChunkCount = (uint)localChunks.Count
        };

        resp.Chunks.AddRange(localChunks.Select(c => new Chunk
        {
            Seq = c.chunkInfo.ChunkSequence,
            Size = c.chunkInfo.ChunkSize,
            Hash = ByteString.CopyFrom([.. c.chunkInfo.ChunkHash])
        }));

        ServerChunks.TryAdd(ticket, [.. localChunks]);
        appContext.Logger?.LogDebug("File {Filename} carved into {ChunkCount} chunks for peer {PeerShortName} with ticket {Ticket}", fileTreeNode.AbsolutePath, localChunks.Count, requestContext.PeerShortName, ticket);

        return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
            appContext,
            resp,
            cc.SessionSharedKey), cancellationToken);
    }

    private async Task<bool> HandleGetChunk(IRequestContext requestContext, ChunkRequest cr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(cr);

        if (appContext == null)
            throw new InvalidOperationException("App is not initialized");

        var cacheKey = DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint);
        if (!ClientConnections.TryGetValue(cacheKey, out ClientConnection? cc))
        {
            appContext.Logger?.LogDebug("GetChunk received from {SourceThumbprint}, but not recorded as a client connection. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint));
            return true;
        }

        appContext.Logger?.LogDebug("GetChunk from {SourceThumbprint} via {PeerShortName}", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), requestContext.PeerShortName);

        if (!ServerChunks.TryGetValue(cr.DownloadTicket, out (ChunkInfo chunkInfo, string chunkFileName)[]? chunks))
        {
            appContext.Logger?.LogDebug("Get chunk from {SourceThumbprint} referenced unknown download ticket {Ticket}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), cr.DownloadTicket);
            return true;
        }

        if (cr.ChunkSeq < 1 || cr.ChunkSeq > chunks.Length)
        {
            appContext.Logger?.LogDebug("Get chunk from {SourceThumbprint} for ticket {Ticket} referenced invalid chunk sequence {Sequence}. Ignoring.", DisplayUtils.BytesToHex(requestContext.RequestSourceThumbprint), cr.DownloadTicket, cr.ChunkSeq);
            return true;
        }

        var (chunkInfo, chunkFileName) = chunks[cr.ChunkSeq - 1];

        if (!File.Exists(chunkFileName))
        {
            return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
                appContext,
                new Status
                {
                    Operation = Operation.GetChunk,
                    StatusCode = 404,
                    StatusMessage = $"Chunk {chunkInfo.ChunkSequence}/{chunks.Length} ({chunkInfo.ChunkSize} bytes) for {chunkInfo.FileName} not found on fserve",
                    ResultPayload = ByteString.Empty
                },
                cc.SessionSharedKey), cancellationToken);
        }

        var payload = await File.ReadAllBytesAsync(chunkFileName, cancellationToken);

        return await appContext.SendMessage(requestContext.RequestSourceThumbprint, FrameUtils.WrapServerFrame(
            appContext,
            new ChunkResponse
            {
                DownloadTicket = cr.DownloadTicket,
                ChunkSeq = chunkInfo.ChunkSequence,
                Payload = ByteString.CopyFrom(payload),
            },
            cc.SessionSharedKey), cancellationToken);
    }

}