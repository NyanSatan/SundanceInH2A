import struct
import argparse
from dataclasses import dataclass

DT_KEY_LEN = 0x20

def align4(v: int) -> int:
    return (v + (4 - 1)) & ~(4 - 1)

DT_PROP_HDR_LEN = DT_KEY_LEN + 4

@dataclass
class DTProperty:
    name: str
    flags: int
    data: bytes

    @property
    def len(self) -> int:
        return len(self.data)

    @classmethod
    def decode(cls, raw: bytes) -> tuple["DTProperty", int]:
        try:
            end = raw.index(b"\0", 0, DT_KEY_LEN)
        except ValueError:
            end = DT_KEY_LEN

        name = raw[:end].decode("ascii")
        length = struct.unpack("<I", raw[DT_KEY_LEN:DT_KEY_LEN + 4])[0]
        flags = (length & 0xF000_0000) >> 24
        length &= ~0xF000_0000

        data = raw[DT_PROP_HDR_LEN : DT_PROP_HDR_LEN + length]

        return cls(name, flags, data), DT_PROP_HDR_LEN + align4(length)

    def encode(self) -> bytes:
        res = bytearray(DT_KEY_LEN)

        res[:len(self.name)] = self.name.encode("ascii")

        res += struct.pack("<I", len(self.data) | (self.flags << 24))
        res += self.data.ljust(align4(len(self.data)), b"\0")

        return res

@dataclass
class DTNode:
    name: str | None
    props: list[DTProperty]
    children : list["DTNode"]

    @property
    def nprop(self) -> int:
        return len(self.props)

    @property
    def nchlid(self) -> int:
        return len(self.children)

    @classmethod
    def _decode_internal(cls, raw: bytes) -> tuple["DTNode", int]:
        nprop, nchild = struct.unpack("<II", raw[:8])
        name = None
        props = list()
        children = list()

        curr_off = 8

        for _ in range(nprop):
            prop, length = DTProperty.decode(raw[curr_off:])
            props.append(prop)

            if prop.name == "name":
                end = prop.data.index(b"\0")
                if end == -1:
                    end = prop.len

                name = prop.data[:end].decode("ascii")

            curr_off += length

        for _ in range(nchild):
            child, length = cls._decode_internal(raw[curr_off:])
            children.append(child)

            curr_off += length

        return cls(name, props, children), curr_off

    @classmethod
    def decode(cls, raw: bytes) -> "DTNode":
        root, _ = cls._decode_internal(raw)
        return root
    
    def add_prop(self, prop: str, data: bytes):
        self.props.append(DTProperty(prop, 0, data))

    def add_child(self, data: bytes):
        self.children.append(DTNode.decode(data))

    def remove_prop(self, prop: str):
        self.props.remove(self.find_prop(prop))

    def encode(self) -> bytes:
        res = bytearray()

        res += struct.pack("<II", self.nprop, self.nchlid)

        for prop in self.props:
            res += prop.encode()

        for child in self.children:
            res += child.encode()

        return res

    def iterate(self, callback, depth: int = 0, path_so_far: list = []):
        if not callback(self, depth, path_so_far + [self.name]):
            return

        for child in self.children:
            child.iterate(callback, depth + 1, path_so_far + [self.name])

        return True

    def find_node(self, path: str) -> "DTNode | None":
        found = None
        tokens = path.split("/")

        def cb(node: DTNode, depth: int, path_so_far: list):
            nonlocal found, tokens

            if found:
                return False

            if path_so_far == tokens:
                found = node
                return False

            return True

        self.iterate(cb)

        return found

    def find_prop(self, prop: str) -> DTProperty | None:
        return next(filter(lambda x: x.name == prop, self.props), None)

PATHS_TO_IGNORE = [
#    "device-tree/arm-io/i2s0/audio0"
]

def do_diff(args):
    with open(args.one, "rb") as f:
        buf = f.read()

    root_one = DTNode.decode(buf)

    with open(args.two, "rb") as f:
        buf = f.read()

    root_two = DTNode.decode(buf)

    differences = list()
    path_nodes = list()
    prev_depth = -1

    def cb(node: DTNode, depth: int, path_so_far: list):
        nonlocal prev_depth

        for _ in range(prev_depth - depth + 1):
            path_nodes.pop()

        path_nodes.append(node.name)

        prev_depth = depth

        path = "/".join(path_nodes)

        if path in PATHS_TO_IGNORE:
            return

        two_node = root_two.find_node(path)
        if not two_node:
            differences.append(
                "NODE ADD %s %s" % (path, node.encode().hex())
            )
            return False

        for one_prop in node.props:
            try:
                two_prop = next(filter(lambda x: x.name == one_prop.name, two_node.props))
            except StopIteration:
                differences.append(
                    "PROP ADD %s %s %s" % (one_prop.name, one_prop.data.hex(), path)
                )
                continue

            if two_prop.name != "AAPL,phandle" and not two_prop.name.startswith("function-") and not two_prop.name.endswith("-parent"):
                if two_prop.data != one_prop.data:
                    differences.append(
                        "PROP SET %s %s %s" % (two_prop.name, one_prop.data.hex(), path)
                    )

        for two_prop in two_node.props:
            try:
                next(filter(lambda x: x.name == two_prop.name, node.props))
            except StopIteration:
                differences.append(
                    "PROP REMOVE %s %s" % (two_prop.name, path)
                )

        return True

    root_one.iterate(cb)

    print("\n".join(differences))

def do_apply(args):
    with open(args.dt, "rb") as f:
        dt_buf = f.read()

    dt = DTNode.decode(dt_buf)

    with open(args.diff, "r") as f:
        diff_buf = f.read()

    for l in diff_buf.splitlines():
        if not l or l.startswith("#"):
            continue

        expr = l.split(" ")

        typ = expr[0]
        act = expr[1]

        if typ == "PROP":
            if act == "ADD":
                name = expr[2]
                data = bytes.fromhex(expr[3])
                path = expr[4]

                node = dt.find_node(path)
                if not node:
                    print("node @ %s was NOT found" % name)
                    continue

                node.add_prop(name, data)

            elif act == "SET":
                name = expr[2]
                data = bytes.fromhex(expr[3])
                path = expr[4]

                node = dt.find_node(path)
                prop = node.find_prop(name)
                if not prop:
                    print("prop @ %s was NOT found" % name)
                    continue

                prop.data = data

            elif act == "REMOVE":
                name = expr[2]
                path = expr[3]

                node = dt.find_node(path)
                node.remove_prop(name)

            else:
                raise ValueError("unknown action for PROP - %s" % act)

        elif typ == "NODE":
            if act == "ADD":
                path = expr[2]
                data = bytes.fromhex(expr[3])

                idx = path.rindex("/")
                path = path[:idx]

                node = dt.find_node(path)
                node.add_child(data)
            else:
                raise ValueError("unknown action for PROP - %s" % act)

        else:
            raise ValueError("unknown type - %s" % typ)

    encoded = dt.encode()

    with open(args.out, "wb") as f:
        f.write(encoded)

from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser("ddt", description="DeviceTree diffing & patching tool")

    subparsers = parser.add_subparsers()

    diff_parser = subparsers.add_parser("diff")
    diff_parser.set_defaults(func=do_diff)
    diff_parser.add_argument("one", type=Path, help="first DeviceTree")
    diff_parser.add_argument("two", type=Path, help="second DeviceTree")

    apply_parser = subparsers.add_parser("apply")
    apply_parser.set_defaults(func=do_apply)
    apply_parser.add_argument("dt", type=Path, help="DeviceTree to apply diff onto")
    apply_parser.add_argument("out", type=Path, help="output DeviceTree")
    apply_parser.add_argument("diff", type=Path, help="diff file")

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        exit(-1)

    args.func(args)

