import logging

VERSION = 0

logger = logging.getLogger("ACChat")

class BitHelper:
    def __init__(self, data):
        self.data = int.from_bytes(data, "big")
        self.offset = 0
        self.length = len(data) * 8

    def read(self, amount):
        shift = self.length - self.offset - amount
        value = (self.data >> shift) & ((1 << amount) - 1)
        self.offset += amount
        return value

    def write(self, value, amount):
        if value >= (1 << amount):
            raise ValueError(f"{value} does not fit into {amount} bits")

        shift = self.length - self.offset - amount
        mask = ((1 << amount) - 1) << shift

        self.data &= ~mask
        self.data |= value << shift

        self.offset += amount

    def change_offset(self, change):
        self.offset += change

    def to_bytes(self):
        return self.data.to_bytes(self.length // 8, "big")

def parse_packet(packet, own_sid):
    helper = BitHelper(packet)

    version = helper.read(3)
    if version > VERSION:
        logger.warning("Unsupported packet version %s received, dropping it", version)
        return ("DROPPED", None)

    sequence_number = helper.read(32)
    packet_type = helper.read(3)
    source_sid = helper.read(96)

    if packet_type == 0:
        target_sid = helper.read(96)
        if target_sid == own_sid:
            case = "RESPOND_TO_QUERY"
        else:
            helper.read(512)
            if not decrease_ttl(helper):
                logger.info("Dropped packet %s from %s because TTL expired", sequence_number, source_sid)
                return ("DROPPED", None)
            return ("FORWARD", {"packet": helper.to_bytes(), "sequence_number": sequence_number})
    elif packet_type == 1:
        target_sid = helper.read(96)
        if target_sid == own_sid:
            case = "QUERY_RESPONSE"
            public_key = helper.read(256)
        else:
            helper.read(512)
            if not decrease_ttl(helper):
                logger.info("Dropped packet %s from %s because TTL expired", sequence_number, source_sid)
                return ("DROPPED", None)
            return ("FORWARD", {"packet": helper.to_bytes(), "sequence_number": sequence_number})
    elif packet_type == 2:
        target_sid = helper.read(96)
        payload_length = helper.read(12)
        payload = helper.read(payload_length)
        if target_sid == own_sid:
            case = "MESSAGE_RECEIVED"
        else:
            helper.read(512)
            if not decrease_ttl(helper):
                logger.info("Dropped packet %s from %s because TTL expired", sequence_number, source_sid)
                return ("DROPPED", None)
            return ("FORWARD", {"packet": helper.to_bytes(), "sequence_number": sequence_number})
    else:
        logger.warning("Malformed Packet (Expected type 0-2, got %s)", packet_type)
        return ("DROPPED", None)

    signature = helper.read(512)
    if case == "RESPOND_TO_QUERY":
        return (case, {"signature": signature, "source_sid": source_sid, "sequence_number": sequence_number})
    elif case == "QUERY_RESPONSE":
        return (case, {"signature": signature, "source_sid": source_sid, "public_key": public_key, "sequence_number": sequence_number}) # pyright: ignore[reportPossiblyUnboundVariable]
    elif case == "MESSAGE_RECEIVED":
        return (case, {"signature": signature, "source_sid": source_sid, "payload": payload, "sequence_number": sequence_number}) # pyright: ignore[reportPossiblyUnboundVariable]

def decrease_ttl(helper):
    ttl = helper.read(5)
    if ttl == 0:
        return False
    helper.change_offset(-5)
    helper.write(ttl-1, 5)
    return True
