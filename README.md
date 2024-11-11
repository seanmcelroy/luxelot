# Luxelot

## Summary

Luxelot is a peer-to-peer (p2p) network for establishing encrypted channels between nodes and passing messages between them.  Luxelot exclusively uses post-quantum cryptography (PQC).

## Concepts

Nodes generate an identity in the form of a CRYSTALS Dilithium public key which is presented when handshaking with other peers and subsequently used to sign messages for forwarding around the network.  Nodes refer to network locations by the SHA-256 hash of their Dilithium public keys.

Peers establish shared secrets using the CRYSTALS Kyber Key Encapsulation Mechanism (KEM).  Kyber is used only between neighboring peers to envelop messages for trading among peers.  Each p2p connection uses its own shared secret that has a lifetime only as long as that network connection between those two peers.