from bitstream import BitWriter
from constants import DEFAULT_TTL, PACKET_TYPE_QUERY_RESPONSE, PACKET_TYPE_SEND, PROTOCOL_VERSION, PACKET_TYPE_QUERY

def construct_packet(sequence_number: int, source_sid: bytes, packet_type: int):
    writer = BitWriter()
    writer.write(DEFAULT_TTL, 5)
    writer.write(PROTOCOL_VERSION, 3)
    writer.write(sequence_number, 32)
    writer.write(packet_type, 3)
    writer.write(int.from_bytes(source_sid, "big"), 96)

    return writer

def construct_query_packet(sequence_number: int, source_sid: bytes, target_sid: bytes):
    writer = construct_packet(sequence_number, source_sid, PACKET_TYPE_QUERY)
    writer.write_bytes(target_sid)

    return writer.to_bytes()

def construct_query_response_packet(sequence_number: int, source_sid: bytes, target_sid: bytes, public_key: bytes):
    writer = construct_packet(sequence_number, source_sid, PACKET_TYPE_QUERY_RESPONSE)
    writer.write_bytes(target_sid)
    writer.write_bytes(public_key)

    return writer.to_bytes()

def construct_send_packet(sequence_number: int, source_sid: bytes, target_sid: bytes, payload: bytes):
    writer = construct_packet(sequence_number, source_sid, PACKET_TYPE_SEND)
    writer.write_bytes(target_sid)
    writer.write(len(payload), 12)
    writer.write_bytes(payload)

    return writer.to_bytes()

def append_signature(packet: bytes, signature: bytes):
    writer = BitWriter()

    writer.write_bytes(packet)
    writer.write_bytes(signature)

    return writer.to_bytes()
