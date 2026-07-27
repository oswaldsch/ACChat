class BitHelper:
    def __init__(self, data: bytes):
        self.data = int.from_bytes(data, "big")
        self.offset = 0
        self.length = len(data) * 8

    def read(self, amount: int) -> int:
        shift = self.length - self.offset - amount
        value = (self.data >> shift) & ((1 << amount) - 1)
        self.offset += amount
        return value

    def change_offset(self, change: int):
        self.offset += change

    def read_bytes(self, byte_amount: int) -> bytes:
        return self.read(byte_amount * 8).to_bytes(byte_amount, "big")


class BitWriter:
    def __init__(self):
        self.data = 0
        self.length = 0

    def write(self, value: int, amount: int):
        if value >= (1 << amount):
            raise ValueError(f"{value} does not fit into {amount} bits")

        self.data = (self.data << amount) | value
        self.length += amount

    def write_bytes(self, data: bytes):
        self.write(int.from_bytes(data, "big"), len(data) * 8)

    def to_bytes(self) -> bytes:
        byte_length = (self.length + 7) // 8
        padding = byte_length * 8 - self.length
        return (self.data << padding).to_bytes(byte_length, "big")
