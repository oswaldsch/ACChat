from dataclasses import dataclass


@dataclass
class Packet:
    version: int
    sequence_number: int
    source_sid: bytes
    signature: bytes
    ttl: int


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
class ForwardPacket:
    data: bytes
    source_sid: bytes
    sequence_number: int

@dataclass
class ParseResult:
    action: str
    reason: str | None = None
    packet: Packet | ForwardPacket | None = None
