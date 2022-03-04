# Unix SMB/CIFS implementation.
# Copyright (C) Catalyst.Net Ltd 2022
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from samba.dcerpc import claims


def decompress(data, compression_type, uncompressed_size):
    if compression_type == claims.CLAIMS_COMPRESSION_FORMAT_NONE:
        return data
    elif compression_type == claims.CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF:
        return lz77_huffman_decompress(data, uncompressed_size)
    else:
        raise AssertionError(f'compression type {compression_type} '
                             f'not supported')


def lz77_huffman_decompress(data, decompressed_size):
    def get_16_bits(data, pos):
        return data[pos] + (data[pos + 1] << 8)

    output = []

    symbol_bit_lengths = []
    for pair in data[:256]:
        symbol_bit_lengths.append(pair & 0xf)
        symbol_bit_lengths.append(pair >> 4)

    # Loop until a decompression terminating condition.
    while True:
        # Build the decoding table.
        decoding_table = []
        for bit_len in range(1, 16):
            for symbol in range(0, 512):
                encoded_bit_length = symbol_bit_lengths[symbol]
                if encoded_bit_length == bit_len:
                    count = (1 << (15 - bit_len))
                    decoding_table.extend([symbol] * count)

        if len(decoding_table) != 2 ** 15:
            raise AssertionError(f'Error constructing decoding table (len = '
                                 f'{len(decoding_table)}')

        # Start at the end of the Huffman table.
        current_pos = 256

        next_bits = get_16_bits(data, current_pos)
        current_pos += 2

        next_bits <<= 16
        next_bits |= get_16_bits(data, current_pos)
        current_pos += 2

        extra_bit_count = 16
        block_end = len(output) + 65536

        # Loop until a block terminating condition.
        while len(output) < block_end:
            huffman_symbol = decoding_table[next_bits >> (32 - 15)]

            huffman_symbol_bit_len = symbol_bit_lengths[huffman_symbol]
            next_bits <<= huffman_symbol_bit_len
            next_bits &= 0xffffffff
            extra_bit_count -= huffman_symbol_bit_len

            if extra_bit_count < 0:
                next_bits |= get_16_bits(data, current_pos) << -extra_bit_count
                extra_bit_count += 16
                current_pos += 2

            if huffman_symbol < 256:
                output.append(huffman_symbol)

            elif (huffman_symbol == 256 and current_pos == len(data)
                      and len(output) == decompressed_size):
                return bytes(output)
            else:
                huffman_symbol -= 256

                match_len = huffman_symbol & 0xf
                match_offset_bit_len = huffman_symbol >> 4

                if match_len == 15:
                    match_len = data[current_pos]
                    current_pos += 1

                    if match_len == 255:
                        match_len = get_16_bits(data, current_pos)
                        current_pos += 2

                        if match_len < 15:
                            raise AssertionError(f'match_len is too small! '
                                                 f'({match_len} < 15)')
                        match_len -= 15
                    match_len += 15
                match_len += 3

                match_offset = next_bits >> (32 - match_offset_bit_len)
                match_offset |= 1 << match_offset_bit_len

                next_bits <<= match_offset_bit_len
                next_bits &= 0xffffffff

                extra_bit_count -= match_offset_bit_len
                if extra_bit_count < 0:
                    next_bits |= (
                        get_16_bits(data, current_pos) << -extra_bit_count)
                    extra_bit_count += 16
                    current_pos += 2

                for i in range(len(output) - match_offset,
                               len(output) - match_offset + match_len):
                    output.append(output[i])

    raise AssertionError('Should not get here')
