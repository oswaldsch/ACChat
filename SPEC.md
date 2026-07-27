## General Packet
Basic Packet Layout for every Request
| Field          | Bits | Expressable     |
|----------------|------|-----------------|
|TTL             |5     |0-31             |
|Version         |3     |0-7              |
|Sequence Number |32    |0-4,294,967,295  |
|Type            |3     |0-7              |
|Source SID      |96    |Trunc. SHA-256   |
|Type-specific Fields (see below)
|Signature       |512   |Ed25519 Signature|

> ### Notes
> Signature signs everything above it
> TTL is the only thing that is left unsigned so it can be modified per Hop without breaking the Signature
> Sequence Number gets increased locally by the Node everytime it originates a Packet.

## Type-Specific

## Query Packet
**Type:0**

Sent when a Node receives a Message whos identity it cant decipher because of a missing Public Key stored for the specific SID

| Field      | Bits | Expressable   |
|------------|------|---------------|
|Target SID  |96    |Trunc. SHA-256 |

## Query Reponse Packet
**Type:1**

Sent as a response by the Owner of the Public Key as a Response to a Query that was directed at its SID
| Field      | Bits | Expressable      |
|------------|------|------------------|
|Target SID  |96    |Trunc. SHA-256    |
|Public Key  |256   |Ed25519 Public Key|

## Send Packet
**Type:2**

Sent when a Node wants to send another Node a message.
| Field        | Bits | Expressable            |
|--------------|------|------------------------|
|Target SID           |96    |Trunc. SHA-256          |
|Payload-Length       |12    |0-4095 Bytes            |
|Payload              |-     |Capped at Payload-Length|
