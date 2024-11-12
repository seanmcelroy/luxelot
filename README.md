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