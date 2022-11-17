/*
 * Samba compression library - LGPLv3
 *
 * Copyright © Catalyst IT 2022
 *
 * Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
 *        and Joseph Sutton   <josephsutton@catalyst.net.nz>
 *
 *  ** NOTE! The following LGPL license applies to this file.
 *  ** It does NOT imply that all of Samba is released under the LGPL
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 3 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <talloc.h>

#include "replace.h"
#include "lzxpress_huffman.h"
#include "lib/util/stable_sort.h"
#include "lib/util/byteorder.h"
#include "lib/util/bytearray.h"


#define LZXPRESS_ERROR -1LL


struct bitstream {
	const uint8_t *bytes;
	size_t byte_pos;
	size_t byte_size;
	uint32_t bits;
	int remaining_bits;
	uint16_t *table;
};


/**
 * Determines the sort order of one prefix_code_symbol relative to another
 */
static int compare_uint16(const uint16_t *a, const uint16_t *b)
{
	if (*a < *b) {
		return -1;
	}
	if (*a > *b) {
		return 1;
	}
	return 0;
}


static bool fill_decomp_table(struct bitstream *input)
{
	/*
	 * There are 512 symbols, each encoded in 4 bits, which indicates
	 * their depth in the Huffman tree. The even numbers get the lower
	 * nibble of each byte, so that the byte hex values look backwards
	 * (i.e. 0xab encodes b then a). These are allocated Huffman codes in
	 * order of appearance, per depth.
	 *
	 * For example, if the first two bytes were:
	 *
	 * 0x23 0x53
	 *
	 * the first four codes have the lengths 3, 2, 3, 5.
	 * Let's call them A, B, C, D.
	 *
	 * Suppose there is no other codeword with length 1 (which is
	 * necessarily true in this example) or 2, but there might be others
	 * of length 3 or 4. Then we can say this about the codes:
	 *
	 *        _ --*--_
	 *      /          \
	 *     0           1
	 *    / \         / \
	 *   0   1       0   1
	 *  B    |\     / \  |\
	 *       0 1   0   1 0 1
	 *       A C   |\ /| | |\
	 *
	 * pos bits  code
	 * A    3    010
	 * B    2    00
	 * C    3    011
	 * D    5    1????
	 *
	 * B has the shortest code, so takes the leftmost branch, 00. That
	 * ends the branch -- nothing else can start with 00. There are no
	 * more 2s, so we look at the 3s, starting as far left as possible. So
	 * A takes 010 and C takes 011. That means everything else has to
	 * start with 1xx. We don't know how many codewords of length 3 or 4
	 * there are; if there are none, D would end up with 10000, the
	 * leftmost available code of length 5. If the compressor is any good,
	 * there should be no unused leaf nodes left dangling at the end.
	 *
	 * (this is "Canonical Huffman Coding").
	 *
	 *
	 * But what symbols do these codes actually stand for?
	 * --------------------------------------------------
	 *
	 * Good question. The first 256 codes stand for the corresponding
	 * literal bytes. The codes from 256 to 511 stand for LZ77 matches,
	 * which have a distance and a length, encoded in a strange way that
	 * isn't entirely the purview of this function.
	 *
	 * What does the value 0 mean?
	 * ---------------------------
	 *
	 * The code does not occur. For example, if the next byte in the
	 * example above was 0x07, that would give the byte 0x04 a 7-long
	 * code, and no code to the 0x05 byte, which means we there is no way
	 * we going to see a 5 in the decoded stream.
	 *
	 * Isn't LZ77 + Huffman what zip/gzip/zlib do?
	 * -------------------------------------------
	 *
	 * Yes, DEFLATE is LZ77 + Huffman, but the details are quite different.
	 */
	uint16_t symbols[512];
	uint16_t sort_mem[512];
	size_t i, n_symbols;
	ssize_t code;
	uint16_t len, prev_len;
	const uint8_t *table_bytes = input->bytes + input->byte_pos;

	if (input->byte_pos + 260 > input->byte_size) {
		return false;
	}

	n_symbols = 0;
	for (i = 0; i < 256; i++) {
		uint16_t even = table_bytes[i] & 15;
		uint16_t odd = table_bytes[i] >> 4;
		if (even != 0) {
			symbols[n_symbols] = (even << 9) + i * 2;
			n_symbols++;
		}
		if (odd != 0) {
			symbols[n_symbols] = (odd << 9) + i * 2 + 1;
			n_symbols++;
		}
	}
	input->byte_pos += 256;
	if (n_symbols == 0) {
		return false;
	}

	stable_sort(symbols, sort_mem, n_symbols, sizeof(uint16_t),
		    (samba_compare_fn_t)compare_uint16);

	/*
	 * we're using an implicit binary tree, as you'd see in a heap.
	 * table[0] = unused
	 * table[1] = '0'
	 * table[2] = '1'
	 * table[3] = '00'     <-- '00' and '01' are children of '0'
	 * table[4] = '01'     <-- '0' is [0], children are [0 * 2 + {1,2}]
	 * table[5] = '10'
	 * table[6] = '11'
	 * table[7] = '000'
	 * table[8] = '001'
	 * table[9] = '010'
	 * table[10]= '011'
	 * table[11]= '100
	 *'
	 * table[1 << n - 1] = '0' * n
	 * table[1 << n - 1 + x] = n-bit wide x (left padded with '0')
	 * table[1 << n - 2] = '1' * (n - 1)
	 *
	 * table[i]->left =  table[i*2 + 1]
	 * table[i]->right = table[i*2 + 2]
	 * table[0xffff] = unused (16 '0's, max len is 15)
	 *
	 * therefore e.g. table[70] = table[64     - 1 + 7]
	 *                          = table[1 << 6 - 1 + 7]
	 *                          = '000111' (binary 7, widened to 6 bits)
	 *
	 *   and if '000111' is a code,
	 *   '00011', '0001', '000', '00', '0' are unavailable prefixes.
	 *       34      16      7     3    1  are their indices
	 *   and (i - 1) >> 1 is the path back from 70 through these.
	 *
	 * the lookup is
	 *
	 * 1 start with i = 0
	 * 2 extract a symbol bit (i = (i << 1) + bit + 1)
	 * 3 is table[i] == 0xffff?
	 * 4  yes -- goto 2
	 * 4  table[i] & 511 is the symbol, stop
	 *
	 * and the construction (here) is sort of the reverse.
	 *
	 * Most of this table is free space that can never be reached, and
	 * most of the activity is at the beginning (since all codes start
	 * there, and by design the shortest codes are the most common).
	 */
	for (i = 0; i < 32; i++) {
		/* prefill the table head */
		input->table[i] = 0xffff;
	}
	code = -1;
	prev_len = 0;
	for (i = 0; i < n_symbols; i++) {
		uint16_t s = symbols[i];
		uint16_t prefix;
		len = (s >> 9) & 15;
		s &= 511;
		code++;
		while (len != prev_len) {
			code <<= 1;
			code++;
			prev_len++;
		}

		if (code >= 65535) {
			return false;
		}
		input->table[code] = s;
		for(prefix = (code - 1) >> 1;
		    prefix > 31;
		    prefix = (prefix - 1) >> 1) {
			input->table[prefix] = 0xffff;
		}
	}

	/*
	 * check that the last code encodes 11111..., with right number of
	 * ones, pointing to the right symbol -- otherwise we have a dangling
	 * uninitialised symbol.
	 */
	if (code != (1 << (len + 1)) - 2) {
		return false;
	}
	return true;
}


#define CHECK_READ_32(dest)					  \
	do {							  \
		if (input->byte_pos + 4 > input->byte_size) {     \
			return LZXPRESS_ERROR;			   \
		}						   \
		dest = PULL_LE_U32(input->bytes, input->byte_pos); \
		input->byte_pos += 4;				   \
	} while (0)

#define CHECK_READ_16(dest)					  \
	do {							  \
		if (input->byte_pos + 2 > input->byte_size) {     \
			return LZXPRESS_ERROR;			   \
		}						   \
		dest = PULL_LE_U16(input->bytes, input->byte_pos); \
		input->byte_pos += 2;				   \
	} while (0)

#define CHECK_READ_8(dest) \
	do {								\
		if (input->byte_pos >= input->byte_size) {		\
			return LZXPRESS_ERROR;				\
		}							\
		dest = PULL_LE_U8(input->bytes, input->byte_pos);	\
		input->byte_pos++;					\
	} while(0)


static inline ssize_t pull_bits(struct bitstream *input)
{
	if (input->byte_pos + 1 < input->byte_size) {
		uint16_t tmp;
		CHECK_READ_16(tmp);
		input->remaining_bits += 16;
		input->bits <<= 16;
		input->bits |= tmp;
	} else if (input->byte_pos < input->byte_size) {
		uint8_t tmp;
		CHECK_READ_8(tmp);
		input->remaining_bits += 8;
		input->bits <<= 8;
		input->bits |= tmp;
	} else {
		return LZXPRESS_ERROR;
	}
	return 0;
}


/*
 * Decompress a block. The actual decompressed size is returned (or -1 on
 * error). The putative block length is 64k (or shorter, if the message ends
 * first), but a match can run over the end, extending the block. That's why
 * we need the overall output size as well as the block size. A match encoded
 * in this block can point back to previous blocks, but not before the
 * beginning of the message, so we also need the previously decoded size.
 *
 * The compressed block will have 256 bytes for the Huffman table, and at
 * least 4 bytes of (possibly padded) encoded values.
 */
static ssize_t lzx_huffman_decompress_block(struct bitstream *input,
					    uint8_t *output,
					    size_t block_size,
					    size_t output_size,
					    size_t previous_size)
{
	size_t output_pos = 0;
	uint16_t symbol;
	size_t index;
	uint16_t distance_bits_wanted = 0;
	size_t distance = 0;
	size_t length = 0;
	bool ok;
	uint32_t tmp;
	bool seen_eof_marker = false;

	ok = fill_decomp_table(input);
	if (! ok) {
		return LZXPRESS_ERROR;
	}

	/*
	 * Always read 32 bits at the start, even if we don't need them.
	 */
	CHECK_READ_16(tmp);
	CHECK_READ_16(input->bits);
	input->bits |= tmp << 16;
	input->remaining_bits = 32;

	/*
	 * This loop iterates over individual *bits*. These are read from
	 * little-endian 16 bit words, most significant bit first.
	 *
	 * At points in the bitstream, the following are possible:
	 *
	 * # the source word is empty and needs to be refilled from the input
	 *    stream.
	 * # an incomplete codeword is being extended.
	 * # a codeword is resolved, either as a literal or a match.
	 * # a literal is written.
	 * # a match is collecting distance bits.
	 * # the output stream is copied, as specified by a match.
	 * # input bytes are read for match lengths.
	 *
	 * Note that we *don't* specifically check for the EOF marker (symbol
	 * 256) in this loop, because the a precondition for stopping for the
	 * EOF marker is that the output buffer is full (otherwise, you
	 * wouldn't know which 256 is EOF, rather than an actual symbol), and
	 * we *always* want to stop when the buffer is full. So we work out if
	 * there is an EOF in in another loop after we stop writing.
	 */

	index = 0;
	while (output_pos < block_size) {
		uint16_t b;
		if (input->remaining_bits == 16) {
			ssize_t ret = pull_bits(input);
			if (ret) {
				return ret;
			}
		}
		input->remaining_bits--;

		b = (input->bits >> input->remaining_bits) & 1;
		if (length == 0) {
			/* not in a match; pulling a codeword */
			index <<= 1;
			index += b + 1;
			if (input->table[index] == 0xffff) {
				/* incomplete codeword, the common case */
				continue;
			}
			/* found the symbol, reset the code string */
			symbol = input->table[index] & 511;
			index = 0;
			if (symbol < 256) {
				/* a literal, the easy case */
				output[output_pos] = symbol;
				output_pos++;
				continue;
			}

			/* the beginning of a match */
			distance_bits_wanted = (symbol >> 4) & 15;
			distance = 1 << distance_bits_wanted;
			length = symbol & 15;
			if (length == 15) {
				CHECK_READ_8(tmp);
				length += tmp;
				if (length == 255 + 15) {
					/*
					 * note, we discard (don't add) the
					 * length so far.
					 */
					CHECK_READ_16(length);
					if (length == 0) {
						CHECK_READ_32(length);
					}
				}
			}
			length += 3;
		} else {
			/* we are pulling extra distance bits */
			distance_bits_wanted--;
			distance |= b << distance_bits_wanted;
		}

		if (distance_bits_wanted == 0) {
			/*
			 * We have a complete match, and it is time to do the
			 * copy (byte by byte, because the ranges can overlap,
			 * and we might need to copy bytes we just copied in).
			 *
			 * It is possible that this match will extend beyond
			 * the end of the expected block. That's fine, so long
			 * as it doesn't extend past the total output size.
			 */
			size_t end = output_pos + length;
			if (end > output_size ||
			    previous_size + output_pos < distance ||
			    unlikely(end < output_pos)) {
				return LZXPRESS_ERROR;
			}

			for (; output_pos < end; output_pos++) {
				output[output_pos] = \
					output[output_pos - distance];
			}
			distance = 0;
			length = 0;
		}
	}

	if (length != 0 || index != 0) {
		/* it seems like we've hit an early end, mid-code */
		return LZXPRESS_ERROR;
	}

	if (input->byte_pos + 256 < input->byte_size) {
		/*
		 * This block is over, but it clearly isn't the last block, so
		 * we don't want to look for the EOF.
		 */
		return output_pos;
	}
	/*
	 * We won't write any more, but we try to read some more to make sure
	 * we're finishing in a good place. That means we want to see a 256
	 * symbol and then some number of zeroes, possibly zero, but as many
	 * as 32.
	 *
	 * In this we are perhaps a bit stricter than Windows, which
	 * apparently does not insist on the EOF marker, nor on a lack of
	 * trailing bytes.
	 */
	while (true) {
		uint16_t b;
		if (input->remaining_bits == 16) {
			ssize_t ret;
			if (input->byte_pos == input->byte_size) {
				/* FIN */
				break;
			}
			ret = pull_bits(input);
			if (ret) {
				return ret;
			}
		}
		input->remaining_bits--;
		b = (input->bits >> input->remaining_bits) & 1;
		if (seen_eof_marker) {
			/*
			 * we have read an EOF symbols. Now we just want to
			 * see zeroes.
			 */
			if (b != 0) {
				return LZXPRESS_ERROR;
			}
			continue;
		}

		/* we're pulling in a symbol, which had better be 256 */
		index <<= 1;
		index += b + 1;
		if (input->table[index] == 0xffff) {
			continue;
		}

		symbol = input->table[index] & 511;
		if (symbol != 256) {
			return LZXPRESS_ERROR;
		}
		seen_eof_marker = true;
		continue;
	}

	if (! seen_eof_marker) {
		return LZXPRESS_ERROR;
	}

	return output_pos;
}

static ssize_t lzxpress_huffman_decompress_internal(struct bitstream *input,
						    uint8_t *output,
						    size_t output_size)
{
	size_t output_pos = 0;

	if (input->byte_size < 260) {
		return LZXPRESS_ERROR;
	}

	while (input->byte_pos < input->byte_size) {
		ssize_t block_output_pos;
		ssize_t block_output_size;
		size_t remaining_output_size = output_size - output_pos;

		block_output_size = MIN(65536, remaining_output_size);

		block_output_pos = lzx_huffman_decompress_block(
			input,
			output + output_pos,
			block_output_size,
			remaining_output_size,
			output_pos);

		if (block_output_pos < block_output_size) {
			return LZXPRESS_ERROR;
		}
		output_pos += block_output_pos;
		if (output_pos > output_size) {
			/* not expecting to get here. */
			return LZXPRESS_ERROR;
		}
	}

	if (input->byte_pos != input->byte_size) {
		return LZXPRESS_ERROR;
	}

	return output_pos;
}


/*
 * lzxpress_huffman_decompress()
 *
 * output_size must be the expected length of the decompressed data.
 * input_size and output_size are limited to the minimum of UINT32_MAX and
 * SSIZE_MAX. On 64 bit machines that will be UINT32_MAX, or 4GB.
 *
 * @param input_bytes  memory to be decompressed.
 * @param input_size   length of the compressed buffer.
 * @param output       destination for the decompressed data.
 * @param output_size  exact expected length of the decompressed data.
 *
 * @return the number of bytes written or -1 on error.
 */

ssize_t lzxpress_huffman_decompress(const uint8_t *input_bytes,
				    size_t input_size,
				    uint8_t *output,
				    size_t output_size)
{
	uint16_t table[65536];
	struct bitstream input = {
		.bytes = input_bytes,
		.byte_size = input_size,
		.byte_pos = 0,
		.bits = 0,
		.remaining_bits = 0,
		.table = table
	};

	if (input_size > SSIZE_MAX ||
	    input_size > UINT32_MAX ||
	    output_size > SSIZE_MAX ||
	    output_size > UINT32_MAX ||
	    input_size == 0 ||
	    output_size == 0 ||
	    input_bytes == NULL ||
	    output == NULL) {
		/*
		 * We use negative ssize_t to return errors, which is limiting
		 * on 32 bit machines, and the 4GB limit exists on Windows.
		 */
		return  LZXPRESS_ERROR;
	}

	return lzxpress_huffman_decompress_internal(&input,
						    output,
						    output_size);
}


/**
 * lzxpress_huffman_decompress_talloc()
 *
 * The caller must provide the exact size of the expected output.
 *
 * The input_size is limited to the minimum of UINT32_MAX and SSIZE_MAX, but
 * output_size is limited to 256MB due to a limit in talloc. This effectively
 * limits input_size too, as non-crafted compressed data will not exceed the
 * decompressed size by very much.
 *
 * @param mem_ctx      TALLOC_CTX parent for the decompressed buffer.
 * @param input_bytes  memory to be decompressed.
 * @param input_size   length of the compressed buffer.
 * @param output_size  expected decompressed size.
 *
 * @return a talloc'ed buffer exactly output_size in length, or NULL.
 */

uint8_t *lzxpress_huffman_decompress_talloc(TALLOC_CTX *mem_ctx,
					    const uint8_t *input_bytes,
					    size_t input_size,
					    size_t output_size)
{
	ssize_t result;
	uint8_t *output = NULL;
	struct bitstream input = {
		.bytes = input_bytes,
		.byte_size = input_size
	};

	output = talloc_array(mem_ctx, uint8_t, output_size);
	if (output == NULL) {
		return NULL;
	}

	input.table = talloc_array(mem_ctx, uint16_t, 65536);
	if (input.table == NULL) {
		talloc_free(output);
		return NULL;
	}
	result = lzxpress_huffman_decompress_internal(&input,
						      output,
						      output_size);
	talloc_free(input.table);

	if (result != output_size) {
		talloc_free(output);
		return NULL;
	}
	return output;
}
