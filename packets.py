from dataclasses import dataclass


@dataclass
class Packet:
    version: int
    sequence_number: int
    source_sid: int
    signature: int
    ttl: int


@dataclass
class QueryPacket(Packet):
    target_sid: int


@dataclass
class QueryResponsePacket(Packet):
    target_sid: int
    public_key: int


@dataclass
class MessagePacket(Packet):
    target_sid: int
    payload: bytes

@dataclass
class ForwardPacket:
    data: bytes
    source_sid: int
    sequence_number: int

@dataclass
class ParseResult:
    action: str
    reason: str | None = None
    packet: Packet | ForwardPacket | None = None
