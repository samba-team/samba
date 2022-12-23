# Generate test vectors for Windows LZ77 Huffman compression.
#
# Copyright (c) 2022 Catalyst IT
#
# GPLv3+.
#
# This uses the Python ctypes module to access the lower level RTL
# compression functions.

import sys
import argparse
from ctypes import create_string_buffer, byref, windll
from ctypes.wintypes import USHORT, ULONG, LONG, PULONG, LPVOID, CHAR
NTSTATUS = LONG


METHODS = {
    'LZNT1': 2,
    'XPRESS_PLAIN': 3,
    'XPRESS_HUFF': 4,
    '2': 2,
    '3': 3,
    '4': 4
}


class RtlError(Exception):
    pass


def ntstatus_check(status, f, args):
    # 0x117 is STATUS_BUFFER_ALL_ZEROS
    status &= 0xffffffff
    if status in (0, 0x117):
        return status
    msg = {
        0xC0000023: "buffer too small",
        0xC0000242: "bad compression data",
    }.get(status, '')

    raise RtlError(f'NTSTATUS: {status:08X} {msg}')


def wrap(f, result, *args):
    f.restype = result
    f.argtypes = args
    f.errcheck = ntstatus_check
    return f


CompressBuffer = wrap(windll.ntdll.RtlCompressBuffer, NTSTATUS,
                      USHORT, LPVOID, ULONG, LPVOID, ULONG, ULONG, PULONG,
                      LPVOID)


GetCompressionWorkSpaceSize = wrap(windll.ntdll.RtlGetCompressionWorkSpaceSize,
                                   NTSTATUS,
                                   USHORT, PULONG, PULONG)


DecompressBufferEx = wrap(windll.ntdll.RtlDecompressBufferEx,
                          NTSTATUS,
                          USHORT, LPVOID, ULONG, LPVOID, ULONG, PULONG, LPVOID)


def compress(data, format, effort=0):
    flags = USHORT(format | effort)
    workspace_size = ULONG(0)
    fragment_size = ULONG(0)
    comp_len = ULONG(0)
    GetCompressionWorkSpaceSize(flags,
                                byref(workspace_size),
                                byref(fragment_size))
    workspace = create_string_buffer(workspace_size.value)
    output_len = len(data) * 9 // 8 + 260
    output_buf = bytearray(output_len)
    CompressBuffer(flags,
                   (CHAR * 1).from_buffer(data), len(data),
                   (CHAR * 1).from_buffer(output_buf), output_len,
                   4096,
                   byref(comp_len),
                   workspace)
    return output_buf[:comp_len.value]


def decompress(data, format, target_size=None):
    flags = USHORT(format)
    workspace_size = ULONG(0)
    fragment_size = ULONG(0)
    decomp_len = ULONG(0)
    GetCompressionWorkSpaceSize(flags,
                                byref(workspace_size),
                                byref(fragment_size))
    workspace = create_string_buffer(workspace_size.value)
    if target_size is None:
        output_len = len(data) * 10
    else:
        output_len = target_size
    output_buf = bytearray(output_len)

    DecompressBufferEx(format,
                       (CHAR * 1).from_buffer(output_buf), len(output_buf),
                       (CHAR * 1).from_buffer(data), len(data),
                       byref(decomp_len),
                       workspace)
    return output_buf[:decomp_len.value]


def main():
    if sys.getwindowsversion().major < 7:
        print("this probably won't work on your very old version of Windows\n"
              "but we'll try anyway!", file=sys.stderr)

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--decompress', action='store_true',
                        help='decompress instead of compress')
    parser.add_argument('-m', '--method', default='XPRESS_HUFF',
                        choices=list(METHODS.keys()),
                        help='use this compression method')
    parser.add_argument('-e', '--extra-effort', action='store_true',
                        help='use extra effort to compress')

    parser.add_argument('-s', '--decompressed-size', type=int,
                        help=('decompress to this size '
                              '(required for XPRESS_HUFF'))

    parser.add_argument('-o', '--output',
                        help='write to this file')
    parser.add_argument('-i', '--input',
                        help='read data from this file')

    args = parser.parse_args()

    method = METHODS[args.method]

    if all((args.decompress,
            args.decompressed_size is None,
            method == 4)):
        print("a size is required for XPRESS_HUFF decompression")
        sys.exit(1)

    with open(args.input, 'rb') as f:
        data = bytearray(f.read())

    if args.decompress:
        output = decompress(data, method, args.decompressed_size)
    else:
        effort = 1 if args.extra_effort else 0
        output = compress(data, method, effort)

    with open(args.output, 'wb') as f:
        f.write(output)


main()
