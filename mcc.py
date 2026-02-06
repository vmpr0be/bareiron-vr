import socket
import struct
import json
from typing import Optional, Tuple, List, Union
import uuid
from pwn import *

class VarInt:
    @staticmethod
    def encode(value: int) -> bytes:
        result = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            result.append(byte)
            if value == 0:
                break
        return bytes(result)
    
    @staticmethod
    def decode(data: bytes) -> Tuple[int, int]:
        result = 0
        shift = 0
        bytes_read = 0
        
        for byte in data:
            bytes_read += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
        
        return result, bytes_read

class PacketClient:
    def __init__(self, host: str, port: int):
        self.remote = remote(host, port)
        self.buffer = bytearray()

    def _read_bytes(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            chunk = self.remote.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data.extend(chunk)
        return bytes(data)

    def _read_varint(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self._read_bytes(1)[0]
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
            if shift >= 32:
                raise ValueError("VarInt too large")
        return result

    def send_packet(self, packet_id: int, payload: bytes = b""):
        packet_data = VarInt.encode(packet_id) + payload
        length_data = VarInt.encode(len(packet_data))
        self.remote.send(length_data + packet_data)

    def clean(self):
        self.remote.clean()

    def write_byte(self, value: int) -> bytes:
        return struct.pack("!B", value & 0xFF)

    def write_short(self, value: int) -> bytes:
        return struct.pack("!h", value)

    def write_ushort(self, value: int) -> bytes:
        return struct.pack("!H", value & 0xFFFF)

    def write_int(self, value: int) -> bytes:
        return struct.pack("!i", value)

    def write_uint(self, value: int) -> bytes:
        return struct.pack("!I", value & 0xFFFFFFFF)

    def write_long(self, value: int) -> bytes:
        return struct.pack("!q", value)

    def write_ulong(self, value: int) -> bytes:
        return struct.pack("!Q", value & 0xFFFFFFFFFFFFFFFF)

    def write_float(self, value: float) -> bytes:
        return struct.pack("!f", value)

    def write_double(self, value: float) -> bytes:
        return struct.pack("!d", value)

    def write_bool(self, value: bool) -> bytes:
        return self.write_byte(1 if value else 0)

    def write_string(self, s: str) -> bytes:
        encoded = s.encode('utf-8')
        return VarInt.encode(len(encoded)) + encoded

    def write_varint(self, value: int) -> bytes:
        return VarInt.encode(value)

    def write_position(self, x: int, y: int, z: int) -> bytes:
        return self.write_ulong(((x & 0x3FFFFFF) << 38) | ((z & 0x3FFFFFF) << 12) | (y & 0xFFF))

    def close(self) -> None:
        self.remote.close()

    def read_byte(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!B", data, offset)[0], offset + 1

    def read_short(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!h", data, offset)[0], offset + 2

    def read_ushort(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!H", data, offset)[0], offset + 2

    def read_int(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!i", data, offset)[0], offset + 4

    def read_uint(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!I", data, offset)[0], offset + 4

    def read_long(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!q", data, offset)[0], offset + 8

    def read_ulong(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        return struct.unpack_from("!Q", data, offset)[0], offset + 8

    def read_float(self, data: bytes, offset: int = 0) -> Tuple[float, int]:
        return struct.unpack_from("!f", data, offset)[0], offset + 4

    def read_double(self, data: bytes, offset: int = 0) -> Tuple[float, int]:
        return struct.unpack_from("!d", data, offset)[0], offset + 8

    def read_bool(self, data: bytes, offset: int = 0) -> Tuple[bool, int]:
        val, offset = self.read_byte(data, offset)
        return bool(val), offset

    def read_string(self, data: bytes, offset: int = 0) -> Tuple[str, int]:
        length, offset = self.read_varint(data, offset)
        string_data = data[offset:offset + length]
        return string_data.decode('utf-8'), offset + length

    def read_varint(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        result, bytes_read = VarInt.decode(data[offset:])
        return result, offset + bytes_read

    def read_uuid(self, data: bytes, offset: int = 0) -> Tuple[str, int]:
        uuid_bytes = data[offset:offset + 16]
        u = uuid.UUID(bytes=uuid_bytes)
        return str(u), offset + 16
