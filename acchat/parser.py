from .bitstream import BitHelper, BitWriter
from .constants import PROTOCOL_VERSION
from .packets import ForwardPacket, Packet, ParseResult, QueryPacket, MessagePacket, QueryResponsePacket
import logging

logger = logging.getLogger("ACChat.parser")

def parse_packet(packet, own_sid: bytes) -> ParseResult:
    helper = BitHelper(packet)
    packet_data = {}

    packet_data["ttl"] = helper.read(5)

    if packet_data["ttl"] == 0:
        logger.info("Dropped packet because TTL expired")
        return ParseResult(action="DROP", reason="TTL_EXPIRED")

    packet_data["version"] = helper.read(3)
    if packet_data["version"] > PROTOCOL_VERSION:
        logger.warning("Unsupported packet version %s received, dropping it", packet_data["version"])
        return ParseResult(action="DROP", reason="UNSUPPORTED_VERSION")

    packet_data["sequence_number"] = helper.read(32)
    packet_type = helper.read(3)
    packet_data["source_sid"] = helper.read_bytes(12)

    if packet_type == 0:
        packet_data["target_sid"] = helper.read_bytes(12)
        if packet_data["target_sid"] == own_sid:
            case = "RESPOND_TO_QUERY"
        else:
            return forward_or_drop(packet, packet_data)
    elif packet_type == 1:
        packet_data["target_sid"] = helper.read_bytes(12)
        if packet_data["target_sid"] == own_sid:
            case = "QUERY_RESPONSE"
            packet_data["public_key"] = helper.read_bytes(32)
        else:
            return forward_or_drop(packet, packet_data)
    elif packet_type == 2:
        packet_data["target_sid"] = helper.read_bytes(12)
        payload_length = helper.read(12)
        packet_data["payload"] = helper.read_bytes(payload_length)
        if packet_data["target_sid"] == own_sid:
            case = "MESSAGE_RECEIVED"
        else:
            return forward_or_drop(packet, packet_data)
    else:
        logger.warning("Malformed Packet (Expected type 0-2, got %s)", packet_type)
        return ParseResult(action="DROP", reason="MALFORMED")

    packet_data["signature"] = helper.read_bytes(64)

    if case == "RESPOND_TO_QUERY":
        return ParseResult(action="RESPOND_TO_QUERY", packet=QueryPacket(**packet_data))

    elif case == "QUERY_RESPONSE":
        return ParseResult(action="SAVE_QUERY", packet=QueryResponsePacket(**packet_data))

    elif case == "MESSAGE_RECEIVED":
        return ParseResult(action="RECEIVED", packet=MessagePacket(**packet_data))  # pyright: ignore[reportArgumentType]

def decrease_ttl(packet: bytes) -> bytes | None:
    helper = BitHelper(packet)

    ttl = helper.read(5)
    if ttl == 0:
        return None

    writer = BitWriter()

    writer.write(ttl - 1, 5)
    remaining_bits = helper.length - helper.offset
    writer.write(helper.read(remaining_bits), remaining_bits)

    return writer.to_bytes()

def forward_or_drop(packet: bytes, packet_data: dict):
    forwarded = decrease_ttl(packet)
    if forwarded is None:
        logger.info("Dropped packet %s from %s because TTL expired",packet_data["sequence_number"], packet_data["source_sid"])
        return ParseResult(action="DROP", reason="TTL_EXPIRED")
    return ParseResult(action="FORWARD", packet=ForwardPacket(data=forwarded, source_sid=packet_data["source_sid"], sequence_number=packet_data["sequence_number"]))
