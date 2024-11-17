using System.Reflection;
using System.Runtime.Loader;

namespace Luxelot;

public class AppLoader : AssemblyLoadContext
{
    private AssemblyDependencyResolver? _resolver;

    public AppLoader() : base(isCollectible: true)
    {
    }

    public AppLoader(string mainAssemblyToLoadPath) : base(isCollectible: true)
    {
        _resolver = new AssemblyDependencyResolver(mainAssemblyToLoadPath);
    }

    protected override Assembly? Load(AssemblyName name)
    {
        if (_resolver == null)
            return base.Load(name);

        string? assemblyPath = _resolver.ResolveAssemblyToPath(name);
        if (assemblyPath != null)
        {
            return LoadFromAssemblyPath(assemblyPath);
        }

        return null;
    }
}