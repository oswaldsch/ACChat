# Fake simulation for testing
import os


class FakeNetwork:
    def __init__(self, path="radio.bin"):
        self.path = path
        self.offsets = {}

        if not os.path.exists(path):
            open(path, "wb").close()

    def broadcast(self, data: bytes):
        with open(self.path, "ab") as f:
            f.write(len(data).to_bytes(4, "big"))
            f.write(data)

    def receive(self, node_id):
        if node_id not in self.offsets:
            self.offsets[node_id] = 0

        packets = []
        with open(self.path, "rb") as f:
            f.seek(self.offsets[node_id])
            while True:
                length_bytes = f.read(4)
                if len(length_bytes) < 4:
                    break
                length = int.from_bytes(length_bytes, "big")
                data = f.read(length)
                if len(data) < length:
                    break
                packets.append(data)
            self.offsets[node_id] = f.tell()
        return packets
