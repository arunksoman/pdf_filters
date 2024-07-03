import cython
from libc.stdint cimport uint32_t
import re

cdef class ASCII85:
    cdef:
        object hex_re
        object trail_re

    def __cinit__(self):
        self.hex_re = re.compile(rb"([a-f\d]{2})", re.IGNORECASE)
        self.trail_re = re.compile(rb"^(?:[a-f\d]{2}|\s)*([a-f\d])[\s>]*$", re.IGNORECASE)

    @cython.boundscheck(False)
    @cython.wraparound(False)
    cpdef bytes ascii85decode(self, bytes data):
        cdef:
            int n = 0
            uint32_t b = 0
            unsigned char* out
            unsigned char c
            int i, outlen, outidx
            bytes result

        outlen = len(data)  # Maximum possible length
        out = <unsigned char*>cython.malloc(outlen * sizeof(unsigned char))
        if not out:
            raise MemoryError()

        try:
            outidx = 0
            for i in range(len(data)):
                c = data[i]
                if 33 <= c <= 117:  # b'!' <= c <= b'u'
                    n += 1
                    b = b * 85 + (c - 33)
                    if n == 5:
                        out[outidx] = (b >> 24) & 0xFF
                        out[outidx + 1] = (b >> 16) & 0xFF
                        out[outidx + 2] = (b >> 8) & 0xFF
                        out[outidx + 3] = b & 0xFF
                        outidx += 4
                        n = 0
                        b = 0
                elif c == 122:  # b'z'
                    if n != 0:
                        raise ValueError(f"Unexpected 'z' character at position {i}")
                    out[outidx] = 0
                    out[outidx + 1] = 0
                    out[outidx + 2] = 0
                    out[outidx + 3] = 0
                    outidx += 4
                elif c == 126:  # b'~'
                    if n:
                        for _ in range(5 - n):
                            b = b * 85 + 84
                        for j in range(n - 1):
                            out[outidx + j] = (b >> (24 - j * 8)) & 0xFF
                        outidx += n - 1
                    break

            result = out[:outidx]
            return result
        finally:
            cython.free(out)

    cdef unsigned char decode_hex(self, bytes x):
        return <unsigned char>int(x, 16)

    @cython.boundscheck(False)
    @cython.wraparound(False)
    cpdef bytes asciihexdecode(self, bytes data):
        cdef:
            unsigned char* out
            int outlen, outidx
            bytes x
            object m
            bytes result

        outlen = len(data) // 2 + 1  # Maximum possible length
        out = <unsigned char*>cython.malloc(outlen * sizeof(unsigned char))
        if not out:
            raise MemoryError()

        try:
            outidx = 0
            for x in self.hex_re.findall(data):
                out[outidx] = self.decode_hex(x)
                outidx += 1

            m = self.trail_re.search(data)
            if m:
                out[outidx] = self.decode_hex(m.group(1) + b"0")
                outidx += 1

            result = out[:outidx]
            return result
        finally:
            cython.free(out)