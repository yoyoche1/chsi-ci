# -*- coding: utf-8 -*-
"""seal.py —— 构建后就地把 .text 的 sha256 封进 exe 的固定占位符（CHSISEAL 方案）。

正确性要点（避免自指死循环）：
  1) 占位符在 PE 数据区（不在 .text），改它不影响被哈希的对象
  2) 哈希计算前先把 64 字节摘要字段清零 → 运行时同样清零再算 → 自洽
用法:  python seal.py <exe>
"""
import hashlib
import struct
import sys

MAGIC = b"CHSISEAL"


def sections(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    base = e + 24 + optsz
    out = {}
    for i in range(nsec):
        o = base + i * 40
        name = bytes(d[o:o + 8]).rstrip(b"\x00").decode("latin1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
        out[name] = (rptr, rsize)
    return out


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else sys.exit("usage: seal.py <exe>")
    d = bytearray(open(src, "rb").read())
    idx = bytes(d).find(MAGIC)
    if idx < 0:
        sys.exit("seal magic not found")
    for i in range(idx + 8, idx + 72):
        d[i] = 0x30
    secs = sections(d)
    if ".text" not in secs:
        sys.exit("no .text section")
    rptr, rsize = secs[".text"]
    h = hashlib.sha256(bytes(d[rptr:rptr + rsize])).hexdigest()
    d[idx + 8:idx + 72] = h.encode("ascii")
    open(src, "wb").write(bytes(d))
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print("sealed: .text=%dB sha256=%s" % (rsize, h))


if __name__ == "__main__":
    main()
