from acchat.constructor import construct_query_packet, construct_query_response_packet, construct_send_packet, append_signature
from acchat.parser import parse_packet

def test_query_packet_roundtrip():
    source_sid = b"\x01" * 12
    target_sid = b"\x02" * 12
    sequence_number = 123

    raw = construct_query_packet(sequence_number, source_sid, target_sid)
    signed = append_signature(raw, b"\x00" * 64)
    result = parse_packet(signed, target_sid)

    assert result.action == "RESPOND_TO_QUERY"
    assert result.packet.source_sid == source_sid
    assert result.packet.target_sid == target_sid
    assert result.packet.sequence_number == sequence_number

def test_query_response_packet_roundtrip():
    source_sid = b"\x01" * 12
    target_sid = b"\x02" * 12
    sequence_number = 123
    public_key = b"\x00" * 32

    raw = construct_query_response_packet(sequence_number, source_sid, target_sid, public_key)
    signed = append_signature(raw, b"\x00" * 64)
    result = parse_packet(signed, target_sid)

    assert result.action == "SAVE_QUERY"
    assert result.packet.source_sid == source_sid
    assert result.packet.target_sid == target_sid
    assert result.packet.sequence_number == sequence_number

def test_send_packet_roundtrip():
    source_sid = b"\x01" * 12
    target_sid = b"\x02" * 12
    sequence_number = 123
    payload = b"testing payload"

    raw = construct_send_packet(sequence_number, source_sid, target_sid, payload)
    signed = append_signature(raw, b"\x00" * 64)
    result = parse_packet(signed, target_sid)

    assert result.action == "RECEIVED"
    assert result.packet.source_sid == source_sid
    assert result.packet.target_sid == target_sid
    assert result.packet.sequence_number == sequence_number
    assert result.packet.payload == payload
