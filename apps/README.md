# Apps

This directory contains loadable modules the core app can activate at runtime to extend server or client capabilities.  The core app serves as the basic networking framework for Luxelot, and these apps form the useful utilities for Luxelot.  They can be independently created and updated by including a reference to the Luxelot.Apps.Common project and then ensuring the build outputs are copied into the core executing assembly directory for runtime discovery and activation.

## List of Apps

### Fserve 
Fserve is a file serving application protocol that operates over Luxelot.  It provides FTP-like capabilities in a client app that a user of a node can use via the console command line to establish a session with a remote node that also uses this app to provide the Fserve service.  Files can be enumerated, downloaded in chunks, and reassembled, all using end-to-end encryption.

### DHT
DHT is a loadable service that provides Kademila distributed hash tables and brings support for commands for nodes to query, store, and retrieve values from DHTs.

### Ping
Ping is a fundamental interactive liveliness check, which is implemented as a simple loadable app.  This is one is so simple, it serves as an instructive template for creating a new loadable module.

## Copying Build Outputs

Check the `.csproj` file for an app to see how build outputs can be automatically copied.  This is accomplished with a project stanza like so:

```xml
<Target Name="CopyDLLs" AfterTargets="Build">
<Message Text="Copying app build outputs" Importance="High" />

<Copy
    SourceFiles="$(TargetDir)$(ProjectName).dll;$(TargetDir)$(ProjectName).pdb"
    DestinationFolder="../../core/bin/Debug/net9.0" />

<Message Text="Copied app build outputs" Importance="High" />
</Target>
```