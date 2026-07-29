from dataclasses import dataclass


@dataclass
class Packet:
    version: int
    sequence_number: int
    source_sid: bytes
    signature: bytes
    ttl: int
    data: bytes


@dataclass
class QueryPacket(Packet):
    target_sid: bytes


@dataclass
class QueryResponsePacket(Packet):
    target_sid: bytes
    public_key: bytes


@dataclass
class MessagePacket(Packet):
    target_sid: bytes
    payload: bytes

@dataclass
class DroppedPacket: # Make linter happy and maybe future use
    data: bytes
    reason: str

@dataclass
class ForwardPacket:
    data: bytes
    source_sid: bytes
    sequence_number: int

@dataclass
class ParseResult:
    action: str
    packet: Packet | ForwardPacket | DroppedPacket
