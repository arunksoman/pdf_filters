# distutils: language=c
# cython: language_level=3

import cython
from libc.math cimport ceil
from libc.stdint cimport uint8_t, uint32_t
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython.mem cimport PyMem_Malloc, PyMem_Free

cdef extern from "Python.h":
    int PyErr_CheckSignals() except -1

cdef extern from "struct.h":
    int pack(const char *format, ...)
    int unpack(const char *format, ...)
    size_t calcsize(const char *format)

from .pdfexceptions import PDFValueError

# segment structure base
cdef list SEG_STRUCT = [
    (">L", "number"),
    (">B", "flags"),
    (">B", "retention_flags"),
    (">B", "page_assoc"),
    (">L", "data_length"),
]

# segment header literals
cdef uint8_t HEADER_FLAG_DEFERRED = 0b10000000
cdef uint8_t HEADER_FLAG_PAGE_ASSOC_LONG = 0b01000000

cdef uint8_t SEG_TYPE_MASK = 0b00111111

cdef uint8_t REF_COUNT_SHORT_MASK = 0b11100000
cdef uint32_t REF_COUNT_LONG_MASK = 0x1FFFFFFF
cdef uint8_t REF_COUNT_LONG = 7

cdef uint32_t DATA_LEN_UNKNOWN = 0xFFFFFFFF

# segment types
cdef uint8_t SEG_TYPE_IMMEDIATE_GEN_REGION = 38
cdef uint8_t SEG_TYPE_END_OF_PAGE = 49
cdef uint8_t SEG_TYPE_END_OF_FILE = 51

# file literals
cdef bytes FILE_HEADER_ID = b"\x97\x4A\x42\x32\x0D\x0A\x1A\x0A"
cdef uint8_t FILE_HEAD_FLAG_SEQUENTIAL = 0b00000001

@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline bint bit_set(int bit_pos, int value) nogil:
    return (value >> bit_pos) & 1

@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline bint check_flag(int flag, int value) nogil:
    return flag & value

@cython.boundscheck(False)
@cython.wraparound(False)
cdef int masked_value(int mask, int value) except -1:
    cdef int bit_pos
    for bit_pos in range(32):
        if bit_set(bit_pos, mask):
            return (value & mask) >> bit_pos
    raise PDFValueError("Invalid mask or value")

@cython.boundscheck(False)
@cython.wraparound(False)
cdef int mask_value(int mask, int value) except -1:
    cdef int bit_pos
    for bit_pos in range(32):
        if bit_set(bit_pos, mask):
            return (value & (mask >> bit_pos)) << bit_pos
    raise PDFValueError("Invalid mask or value")

@cython.boundscheck(False)
@cython.wraparound(False)
cdef int unpack_int(const char* format, const unsigned char* buffer) nogil:
    cdef int result
    unpack(format, buffer, &result)
    return result

ctypedef dict JBIG2SegmentFlags
ctypedef dict JBIG2RetentionFlags
ctypedef dict JBIG2Segment

cdef class JBIG2StreamReader:
    cdef object stream

    def __cinit__(self, stream):
        self.stream = stream

    cpdef list get_segments(self):
        cdef:
            list segments = []
            JBIG2Segment segment
            str field_format, name
            int field_len
            bytes field
            int value
            object parser

        while not self.is_eof():
            segment = {}
            for field_format, name in SEG_STRUCT:
                field_len = calcsize(field_format)
                field = self.stream.read(field_len)
                if len(field) < field_len:
                    segment["_error"] = True
                    break
                value = unpack_int(field_format.encode(), field)
                parser = getattr(self, f"parse_{name}", None)
                if callable(parser):
                    value = parser(segment, value, field)
                segment[name] = value

            if not segment.get("_error"):
                segments.append(segment)
        return segments

    cpdef bint is_eof(self):
        if self.stream.read(1) == b"":
            return True
        else:
            self.stream.seek(-1, 1)
            return False

    cpdef JBIG2SegmentFlags parse_flags(self, JBIG2Segment segment, int flags, bytes field):
        return {
            "deferred": check_flag(HEADER_FLAG_DEFERRED, flags),
            "page_assoc_long": check_flag(HEADER_FLAG_PAGE_ASSOC_LONG, flags),
            "type": masked_value(SEG_TYPE_MASK, flags),
        }

    cpdef JBIG2RetentionFlags parse_retention_flags(self, JBIG2Segment segment, int flags, bytes field):
        cdef:
            int ref_count = masked_value(REF_COUNT_SHORT_MASK, flags)
            list retain_segments = []
            list ref_segments = []
            int bit_pos, ret_bytes_count, ret_byte_index, ret_byte
            int seg_num, ref_size, ref_index, ref
            bytes ref_data
            const char* ref_format

        if ref_count < REF_COUNT_LONG:
            for bit_pos in range(5):
                retain_segments.append(bit_set(bit_pos, flags))
        else:
            field += self.stream.read(3)
            ref_count = unpack_int(b">L", field)
            ref_count = masked_value(REF_COUNT_LONG_MASK, ref_count)
            ret_bytes_count = int(ceil((ref_count + 1) / 8.0))
            for ret_byte_index in range(ret_bytes_count):
                ret_byte = unpack_int(b">B", self.stream.read(1))
                for bit_pos in range(7):
                    retain_segments.append(bit_set(bit_pos, ret_byte))

        seg_num = segment["number"]
        if seg_num <= 256:
            ref_format = b">B"
        elif seg_num <= 65536:
            ref_format = b">I"
        else:
            ref_format = b">L"

        ref_size = calcsize(ref_format)

        for ref_index in range(ref_count):
            ref_data = self.stream.read(ref_size)
            ref = unpack_int(ref_format, ref_data)
            ref_segments.append(ref)

        return {
            "ref_count": ref_count,
            "retain_segments": retain_segments,
            "ref_segments": ref_segments,
        }

    cpdef int parse_page_assoc(self, JBIG2Segment segment, int page, bytes field):
        if segment["flags"]["page_assoc_long"]:
            field += self.stream.read(3)
            page = unpack_int(b">L", field)
        return page

    cpdef int parse_data_length(self, JBIG2Segment segment, int length, bytes field):
        if length:
            if segment["flags"]["type"] == SEG_TYPE_IMMEDIATE_GEN_REGION and length == DATA_LEN_UNKNOWN:
                raise NotImplementedError("Working with unknown segment length is not implemented yet")
            else:
                segment["raw_data"] = self.stream.read(length)
        return length

cdef class JBIG2StreamWriter:
    cdef:
        object stream
        JBIG2RetentionFlags EMPTY_RETENTION_FLAGS

    def __cinit__(self, stream):
        self.stream = stream
        self.EMPTY_RETENTION_FLAGS = {
            "ref_count": 0,
            "ref_segments": [],
            "retain_segments": [],
        }

    cpdef int write_segments(self, list segments, bint fix_last_page=True) except -1:
        cdef:
            int data_len = 0
            int current_page = -1
            int seg_num = -1
            bytes data
            JBIG2Segment segment
            int seg_page

        for segment in segments:
            data = self.encode_segment(segment)
            self.stream.write(data)
            data_len += len(data)

            seg_num = segment["number"]

            if fix_last_page:
                seg_page = segment.get("page_assoc", 0)

                if segment["flags"]["type"] == SEG_TYPE_END_OF_PAGE:
                    current_page = -1
                elif seg_page:
                    current_page = seg_page

        if fix_last_page and current_page != -1 and seg_num != -1:
            segment = self.get_eop_segment(seg_num + 1, current_page)
            data = self.encode_segment(segment)
            self.stream.write(data)
            data_len += len(data)

        return data_len

    cpdef int write_file(self, list segments, bint fix_last_page=True) except -1:
        cdef:
            bytes header = FILE_HEADER_ID
            uint8_t header_flags = FILE_HEAD_FLAG_SEQUENTIAL
            bytes number_of_pages
            int data_len
            int seg_num = 0
            int seg_num_offset
            JBIG2Segment eof_segment
            bytes data

        header += pack(b">B", header_flags)
        number_of_pages = pack(b">L", 1)
        header += number_of_pages
        self.stream.write(header)
        data_len = len(header)

        data_len += self.write_segments(segments, fix_last_page)

        for segment in segments:
            seg_num = segment["number"]

        if fix_last_page:
            seg_num_offset = 2
        else:
            seg_num_offset = 1
        eof_segment = self.get_eof_segment(seg_num + seg_num_offset)
        data = self.encode_segment(eof_segment)

        self.stream.write(data)
        data_len += len(data)

        return data_len

    cpdef bytes encode_segment(self, JBIG2Segment segment):
        cdef:
            bytes data = b""
            str field_format, name
            object value, encoder
            bytes field

        for field_format, name in SEG_STRUCT:
            value = segment.get(name)
            encoder = getattr(self, f"encode_{name}", None)
            if callable(encoder):
                field = encoder(value, segment)
            else:
                field = pack(field_format.encode(), value)
            data += field
        return data

    cpdef bytes encode_flags(self, JBIG2SegmentFlags value, JBIG2Segment segment):
        cdef int flags = 0
        if value.get("deferred"):
            flags |= HEADER_FLAG_DEFERRED

        if "page_assoc_long" in value:
            flags |= HEADER_FLAG_PAGE_ASSOC_LONG if value["page_assoc_long"] else flags
        else:
            flags |= HEADER_FLAG_PAGE_ASSOC_LONG if segment.get("page", 0) > 255 else flags

        flags |= mask_value(SEG_TYPE_MASK, value["type"])

        return pack(b">B", flags)

    cpdef bytes encode_retention_flags(self, JBIG2RetentionFlags value, JBIG2Segment segment):
        cdef:
            list flags = []
            str flags_format = ">B"
            int ref_count = value["ref_count"]
            list retain_segments = value.get("retain_segments", [])
            int flags_byte, ref_index, bytes_count, flags_dword, byte_index, ret_byte, bit_pos
            list ref_segments = value.get("ref_segments", [])
            int seg_num = segment["number"]
            const char* ref_format
            int ref

        if ref_count <= 4:
            flags_byte = mask_value(REF_COUNT_SHORT_MASK, ref_count)
            for ref_index, ref_retain in enumerate(retain_segments):
                if ref_retain:
                    flags_byte |= 1 << ref_index
            flags.append(flags_byte)
        else:
            bytes_count = int(ceil((ref_count + 1) / 8.0))
            flags_format = f">L{'B' * bytes_count}"
            flags_dword = mask_value(REF_COUNT_SHORT_MASK, REF_COUNT_LONG) << 24
            flags.append(flags_dword)

            for byte_index in range(bytes_count):
                ret_byte = 0
                ret_part = retain_segments[byte_index * 8 : byte_index * 8 + 8]
                for bit_pos, ret_seg in enumerate(ret_part):
                    ret_byte |= 1 << bit_pos if ret_seg else ret_byte

                flags.append(ret_byte)

        if seg_num <= 256:
            ref_format = b"B"
        elif seg_num <= 65536:
            ref_format = b"I"
        else:
            ref_format = b"L"

        for ref in ref_segments:
            flags_format += ref_format.decode()
            flags.append(ref)

        return pack(flags_format.encode(), *flags)

    cpdef bytes encode_data_length(self, int value, JBIG2Segment segment):
        cdef bytes data = pack(b">L", value)
        data += segment["raw_data"]
        return data

    cpdef JBIG2Segment get_eop_segment(self, int seg_number, int page_number):
        return {
            "data_length": 0,
            "flags": {"deferred": False, "type": SEG_TYPE_END_OF_PAGE},
            "number": seg_number,
            "page_assoc": page_number,
            "raw_data": b"",
            "retention_flags": self.EMPTY_RETENTION_FLAGS,
        }

    cpdef JBIG2Segment get_eof_segment(self, int seg_number):
        return {
            "data_length": 0,
            "flags": {"deferred": False, "type": SEG_TYPE_END_OF_FILE},
            "number": seg_number,
            "page_assoc": 0,
            "raw_data": b"",
            "retention_flags": self.EMPTY_RETENTION_FLAGS,
        }