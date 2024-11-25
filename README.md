# Luxelot

## Summary

Luxelot is a peer-to-peer (p2p) network for establishing encrypted channels between nodes and passing messages between them.  Luxelot exclusively uses post-quantum cryptography (PQC) for all network exchanges.

## News

This is a very, very alpha project.  Simple things like direct P2P connections using explicit address configuration work, as do some very simple concepts like "ping"/"pong".  There's not much else to this project yet, but more is planned.  A simple file transfer service implemented as an app (see Apps under Concepts below) is the current active focus to exemplify the potential of the project.

## Quickstart

1. Download and build the solution using `dotnet build` in the root directory, which contains the luxelot.sln file.

2. Run the command `dotnet run --project ./core/luxelot.csproj &` (on Linux to run in the background of the shell) which will run the core project, which is the console host.  Wait a minute or so for the nodes defined in the `appsettings.json` file to be spun up.

3. Connect to the console host using telnet or netcat, such as `nc 127.0.0.1 8000`.  You should be greeted with "HELLO."

4. Type `peers` or `help`.  Play!

## Concepts

### Apps

Luxelot has the concept of loadable modules, called "apps" which either provide custom message handling or dispatch and/or custom console commands.  A simple "ping" app is included which implements an application-level ping/pong request and response either with a direct neigherboring peer or through a directed broadcast across the network.  Each app in this solution is a separate .NET project under the apps project.  Each app copies its build outputs into the "core" console project's build output directory.  The core console host dynamically loads each app on start-up, which allows apps to be independently developed and tested.

### Cryptography

Nodes generate an identity in the form of a CRYSTALS-Dilithium public key which is presented when handshaking with other peers and subsequently used to sign messages for forwarding around the network.  Nodes refer to network locations by the SHA-256 hash of their Dilithium public keys.

Peers establish shared secrets using the CRYSTALS-Kyber Key Encapsulation Mechanism (KEM).  Kyber is used only between neighboring peers to envelop messages for trading among peers.  Each p2p connection uses its own shared secret that has a lifetime only as long as that network connection between those two peers.

Messages directly shared between neighboring nodes and those forwarded across the network between remote nodes are signed by the Dilithum key of the sender.  While forwarded messages are not E2EE encrypted, Apps can define their own key exchange messages and implement E2EE as a feature of their app protocol design on top of Luxelot.  (The in-development file server app does this.)

Nodes are aware of the Dilithium public keys of their direct neighbors, but may also learn the public keys of remote nodes if they are shared in forwarded messages.  The thumbprint of a node, a SHA256 hash of a node's public Dilithium key, is shared as the source of messages.  When a node is aware of a sender's public key, either through a direct neighbor handshake or inference from monitoring messages, it will verify signatures of forwarded messages traversing it and will not pass corrupted messages that do not have a signature matching the matching thumbprint it knows.

Bouncy Castle is used for all post-quantum cryptography usage.

### Message Protocol

Messages are encoded using Protocol Buffers (proto3), and are defined in .proto files in the projects that own them.

For more information about the message protocol, see PROTOCOL.md

### Anonymity

Luxelot is not designed (at this time) to provide anonymity.  Traffic analysis, for instance, may be used to identify the network topology or source of a message given enough time.

### Discovery

Luxelot does not yet have a discovery mechanism.  Nodes must be explicitly configured for P2P configurations.  Discovery is a future design goal for this project to allow new nodes to identify local peers on the same subnet, find remote peers in a directory, and publish its existance on the directory.  None of these features exist yet.

### Overlay / Egress to the Interet

Luxelot is a network of peer-to-peer nodes connected over the Internet.  However, Luxelot is not intended to provide onion routing or other relays to access the Internet through Luxelot.  For this reason, there are no proxy or other configurations that allow Luxelot to serve access to the public web or other Internet services.  Luxelot is more of a darknet in that it is a network of services and content, but not necessarily a dark web, since that content is not natively web-based or browser-accessible.

Luxelot is a message-passing network, it is not an Internet Protocol (IP) tunnel or proxy.  For this reason, Luxelot is not designed to provide real-time or streaming services, and applications must be resilient to latency and non-delivery.  In other words, you cannot "browse the web" over Luxelot.  You can use apps and services for Luxelot that are unrelated to existing IP network services.

## How To

This is a very alpha concept build.

Running this spins up three nodes listening for user connections on 8000, 8001, and 8002, respectively, among nodes referred to herein as Alice, Bob, and Carol.  These nodes listen for node-to-node connections on 9000, 9001, and 9002, respectively.  

Type "help" after connecting to node listening at 8001 (Bob) using a tool like telnet, then type ? for a list of commands or type "peers" to see a list of peers.  Alice connects to Bob, and Bob connects to Carol, so from Bob's vantage point, peers should display two peers.  Another command you can try is "ping" which implements a simple ping-pong internal reply.

### Configuration

Luxelot runs as a host console application and reads settings from appsettings.json.  This console host can load any number of nodes, though the typical configuration would be a single node.  This file can also set logging parameters.  An example is provided below:

```json
{
  "NoPassword": true,
  "Nodes": {
    "Instances": {
      "Alice": {
        "ListenAddress": "0.0.0.0",
        "PeerPort": 9000,
        "UserPort": 8000,
        "KnownPeers": [
          "127.0.0.1:9001"
        ],
        "KeyContainer": "alice"
      },
      "Bob": {
        "ListenAddress": "0.0.0.0",
        "PeerPort": 9001,
        "UserPort": 8001,
        "KnownPeers": [
          "127.0.0.1:9002"
        ],
      }
    }
  },
  "Logging": {
    "LogLevel": {
      "Default": "None"
    },
    "Console": {
      "IncludeScopes": true,
      "LogLevel": {
        "Default": "Debug"
      }
    }
  }
}
```

This example creates two listening nodes and informs Alice of Bob so that she can connect.  This allows testing a small closed environment.

The `KeyContainer` parameter is the file into which to save the cryptographic key material for the node.  This file is saved into AppData/luxelot/{KeyContainer}.{RandomExtension}, which on Linux is the ~/.config/luxelot path.  The extension contains data (an IV/salt) used to decrypt the file's contents and must not be changed on the file system or else decryption will fail.  In this example, node "bob" does not specify a key container, and so that node's key material will be recreated on every program run.

The `NoPassword` option sets the password to the literal value "insecure", which can be used to run luxelot headless or without an external terminal when debugging in vscode/vscodium.  There is also a `NoKeyContainerEncryption` option which does not set a password at all.  This is only useful for a Luxelot developer to forego the password hashing time for decrypting key containers in iterative development processes.  Please do not set this in production.

## FAQs

1. Why did you use C# and dotnet?  Wouldn't go or rust be more exciting or better choices for a network application?

Maybe!  I like C# and dotnet on Linux.  Darknets are weird.  I'm weird.  I may rewrite this in some other language someday, but at this stage, I want to prototype quickly in a mature language I know well, so here we are.  By using protobufs and not a custom binary protocol of my making, I'm hopeful that with interface stability, anyone can implement Luxelot in any language and toolkit of their choosing that supports proto3 and post-quantum cryptography.

2. How are keys protected on the local system?

Key containers are encrypted with AES-256 on the local system.  Random bits are used to create an IV/salt value.  It is supplied as a salt with a user-supplied password to ```scrypt``` (a password-based key derivation function) to generate keying material for AES-256.  The same random bits are used as an IV along with this keying material to encrypt the Dilithium keys into a file.  The IV/salt are only ever used to encrypt the key container once and this file is never modified and re-encrypted with the same IV/salt.  Perhaps someday this will get upgraded to Argon2id.

