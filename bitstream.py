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

    def to_bytes(self) -> bytes:
        return self.data.to_bytes(self.length // 8, "big")
