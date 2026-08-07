from collections.abc import Callable

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QLineEdit,
    QVBoxLayout,
    QWidget,
    QLabel,
    QFrame,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from .crypto import generate_keys, generate_sid, sign_data, check_signature, serialize_public_key, deserialize_public_key
from .networking import FakeNetwork
from .constructor import construct_query_packet, construct_query_response_packet, construct_send_packet, append_signature
from .parser import parse_packet
from .packets import Packet, QueryPacket, QueryResponsePacket, DroppedPacket, ForwardPacket, MessagePacket
import sys
import logging

CHAT_STYLESHEET = """
Message {
    border-radius: 10px;
    padding: 0 6px;
    margin: 4px 0;
}
Message[own="true"] {
    background-color: #5676e9;
    margin-left: 50px;
}
Message[own="false"] {
    background-color: #FFFFFF;
    margin-right: 50px;
}
Message[own="true"] QLabel {
    color: #ffffff;
}
Message[own="false"] QLabel {
    color: #000000;
}
"""

logger = logging.getLogger("nodal.client")

class Message(QFrame):
    def __init__(self, content: str, sid: str | None = None):
        super().__init__()
        self.main_layout = QVBoxLayout()
        self.setMaximumWidth(700)
        if sid:
            self.username_label = QLabel(sid)
            self.username_label.setStyleSheet("font-weight: bold;")
            self.main_layout.addWidget(self.username_label)
        self.text = QLabel(content)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        self.main_layout.addWidget(self.text)
        self.text.setWordWrap(True)
        self.setProperty("own", "true" if not sid else "false")
        self.setLayout(self.main_layout)


class MessageArea(QScrollArea):
    def __init__(self):
        super().__init__()
        self.container = QWidget()
        self.setWidget(self.container)
        self.setWidgetResizable(True)

        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.container.setLayout(self.main_layout)

        self.messages: list[Message] = []

    def add_message(self, text: str, sid: str | None = None):
        self.message_row = QHBoxLayout()
        msg = Message(text, sid)
        if not sid:
            self.message_row.addStretch()
        self.message_row.addWidget(msg)
        if sid:
            self.message_row.addStretch()

        self.main_layout.addLayout(self.message_row)
        self.messages.append(msg)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("nodal PoC")
        self.setFixedSize(1300, 800)
        self.setStyleSheet(CHAT_STYLESHEET)

        self.protocol = ProtocolImplementation(on_receive=self.receive_msg, transport=FakeNetwork())

        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout()
        central.setLayout(main_layout)

        title = QLabel("nodal Proof of Concept")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20pt; font-weight: bold;")
        main_layout.addWidget(title)

        your_sid_label = QLabel("Your SID: " + self.protocol.get_sid())
        your_sid_label.setStyleSheet("font-size: 15pt; font-weight: bold;")
        your_sid_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        main_layout.addWidget(your_sid_label)

        self.destination_sid = QLineEdit()
        self.destination_sid.setPlaceholderText("Destination SID")
        main_layout.addWidget(self.destination_sid)

        self.message_area = MessageArea()
        main_layout.addWidget(self.message_area)

        self.message_row = QHBoxLayout()
        self.message_input = QLineEdit()
        self.send_button = QPushButton("Senden")
        self.send_button.clicked.connect(self.send_msg)

        self.message_row.addWidget(self.message_input)
        self.message_row.addWidget(self.send_button)
        main_layout.addLayout(self.message_row)

        self.poll_timer = QTimer()
        self.poll_timer.timeout.connect(self.protocol.poll)
        self.poll_timer.start(50)

    def send_msg(self):
        destination = self.destination_sid.text()
        content = self.message_input.text()
        self.protocol.send_msg(destination, content)
        self.message_input.clear()
        self.message_area.add_message(content)

    def receive_msg(self, sid, message):
        self.message_area.add_message(message, sid)

class ProtocolImplementation:
    def __init__(self, on_receive: Callable[[str, str], None], transport):
        self.private_key, self.public_key = generate_keys()
        self.public_key_raw = serialize_public_key(self.public_key)
        self.sid = generate_sid(self.public_key_raw)

        self.on_receive = on_receive
        self.transport = transport

        self.sequence_number = 0
        self.key_cache = {}
        self.queried_sids = {}
        self.queued_packets = {}
        self.packet_cache = []

    def send_msg(self, target_sid_hex: str, content_str: str):
        target_sid = bytes.fromhex(target_sid_hex)
        content = content_str.encode("utf-8")
        packet = construct_send_packet(self.sequence_number, self.sid, target_sid, content)
        self.send_packet(packet)

    def send_packet(self, packet):
        packet = append_signature(packet, sign_data(drop_ttl(packet), self.private_key))
        self.transport.broadcast(packet)
        self.sequence_number += 1 # Only increment after network request has been made to catch weird edge cases or race conditions

    def receive(self, packet, was_queued=False):
        if drop_ttl(packet) in self.packet_cache and not was_queued:
            logger.info("Dropped duplicate packet")
            return
        result = parse_packet(packet, self.sid)
        self.packet_cache.append(drop_ttl(packet))
        match result.action: # Asserting to make linter happy and maybe catch bugs
            case "DROP":
                assert isinstance(result.packet, DroppedPacket)
                logger.info("Dropped packet: %s", result.packet.reason)
                return
            case "FORWARD":
                assert isinstance(result.packet, ForwardPacket)
                self.transport.broadcast(result.packet.data)
            case "SAVE_QUERY":
                assert isinstance(result.packet, QueryResponsePacket)
                if result.packet.source_sid in self.queried_sids:
                    if generate_sid(result.packet.public_key) == result.packet.source_sid:
                        public_key = deserialize_public_key(result.packet.public_key)
                        if self.verify_packet(result.packet.data, result.packet.signature, public_key, result.packet.source_sid):
                            self.key_cache[result.packet.source_sid] = public_key
                            if result.packet.source_sid in self.queued_packets:
                                for queued in self.queued_packets[result.packet.source_sid]:
                                    self.receive(queued, was_queued=True)
                                del self.queued_packets[result.packet.source_sid]
                    else:
                        logger.warning("Query response from %s contained a public key with mismatching SID", result.packet.source_sid)
                        return
                else:
                    logger.info("Received unexpected Query Response for unknown request from SID %s", result.packet.source_sid)
            case "RESPOND_TO_QUERY":
                assert isinstance(result.packet, QueryPacket)
                packet = construct_query_response_packet(self.sequence_number, self.sid, result.packet.source_sid, self.public_key_raw)
                self.send_packet(packet)
            case "RECEIVED":
                assert isinstance(result.packet, MessagePacket)
                if result.packet.source_sid in self.key_cache:
                    if self.verify_packet(result.packet.data, result.packet.signature, self.key_cache[result.packet.source_sid], result.packet.source_sid):
                        self.on_receive(result.packet.source_sid.hex(), result.packet.payload.decode("utf-8"))
                else:
                    self.query_public_key(result.packet)

    def poll(self):
        for data in self.transport.receive(self.sid):
            self.receive(data)

    def verify_packet(self, data, signature, public_key,source_sid):
        if check_signature(get_signed_data(data), signature, public_key):
            return True
        else:
            logger.warning("Dropped packet from %s (May be modified by an attacker!): Invalid signature", source_sid)
            return False

    def query_public_key(self, packet: Packet):
        query_packet = construct_query_packet(self.sequence_number, self.sid, packet.source_sid)
        self.send_packet(query_packet)
        self.queried_sids[packet.source_sid] = True
        self.queued_packets.setdefault(packet.source_sid, []).append(packet.data)

    def get_sid(self):
        return self.sid.hex()

def drop_signature(packet: bytes) -> bytes:
    if len(packet) < 64:
        raise ValueError("Packet too short for signature")

    return packet[:-64]


def drop_ttl(packet: bytes) -> bytes:
    value = int.from_bytes(packet, "big")

    bit_length = len(packet) * 8
    value &= (1 << (bit_length - 5)) - 1

    new_length = bit_length - 5
    return value.to_bytes((new_length + 7) // 8, "big")


def get_signed_data(packet: bytes) -> bytes:
    return drop_ttl(drop_signature(packet))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
