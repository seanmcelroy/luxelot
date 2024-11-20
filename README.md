# Luxelot

## Summary

Luxelot is a peer-to-peer (p2p) network for establishing encrypted channels between nodes and passing messages between them.  Luxelot exclusively uses post-quantum cryptography (PQC).

## Concepts

Nodes generate an identity in the form of a CRYSTALS Dilithium public key which is presented when handshaking with other peers and subsequently used to sign messages for forwarding around the network.  Nodes refer to network locations by the SHA-256 hash of their Dilithium public keys.

Peers establish shared secrets using the CRYSTALS Kyber Key Encapsulation Mechanism (KEM).  Kyber is used only between neighboring peers to envelop messages for trading among peers.  Each p2p connection uses its own shared secret that has a lifetime only as long as that network connection between those two peers.

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

The `NoPassword` option sets the password to the literal value "insecure", which can be used to run luxelot headless or without an external terminal when debugging in vscode/vscodium.