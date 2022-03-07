/*
 * Copyright (C) Matthieu Suiche 2008
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "replace.h"
#include "lzxpress.h"
#include "../lib/util/byteorder.h"


#define __CHECK_BYTES(__size, __index, __needed) do { \
	if (unlikely(__index >= __size)) { \
		return -1; \
	} else { \
		uint32_t __avail = __size - __index; \
		if (unlikely(__needed > __avail)) { \
			return -1; \
		} \
	} \
} while(0)

ssize_t lzxpress_compress(const uint8_t *uncompressed,
			  uint32_t uncompressed_size,
			  uint8_t *compressed,
			  uint32_t max_compressed_size)
{
	uint32_t uncompressed_pos, compressed_pos, byte_left;
	uint32_t max_offset, best_offset;
	int32_t offset;
	uint32_t max_len, len, best_len, match_len;
	const uint8_t *str1, *str2;
	uint32_t indic;
	uint8_t *indic_pos;
	uint32_t indic_bit, nibble_index;

	uint32_t metadata_size;
	uint16_t metadata;
	uint16_t *dest;

	if (!uncompressed_size) {
		return 0;
	}

	uncompressed_pos = 0;
	indic = 0;
	*(uint32_t *)compressed = 0;
	compressed_pos = sizeof(uint32_t);
	indic_pos = &compressed[0];

	byte_left = uncompressed_size;
	indic_bit = 0;
	nibble_index = 0;

	if (uncompressed_pos > XPRESS_BLOCK_SIZE)
		return 0;

	while ((uncompressed_pos < uncompressed_size) &&
	       (compressed_pos < max_compressed_size)) {
		bool found = false;

		max_offset = uncompressed_pos;

		str1 = &uncompressed[uncompressed_pos];

		best_len = 2;
		best_offset = 0;

		max_offset = MIN(0x1FFF, max_offset);

		/* search for the longest match in the window for the lookahead buffer */
		for (offset = 1; (uint32_t)offset <= max_offset; offset++) {
			str2 = &str1[-offset];

			/* maximum len we can encode into metadata */
			max_len = MIN(0x1FFF, byte_left);

			for (len = 0; (len < max_len) && (str1[len] == str2[len]); len++);

			/*
			 * We check if len is better than the value found before, including the
			 * sequence of identical bytes
			 */
			if (len > best_len) {
				found = true;
				best_len = len;
				best_offset = offset;
			}
		}

		if (!found) {
			__CHECK_BYTES(uncompressed_size, uncompressed_pos, sizeof(uint8_t));
			__CHECK_BYTES(max_compressed_size, compressed_pos, sizeof(uint8_t));
			compressed[compressed_pos++] = uncompressed[uncompressed_pos++];
			byte_left--;

			indic <<= 1;
			indic_bit += 1;

			if (indic_bit == 32) {
				PUSH_LE_U32(indic_pos, 0, indic);
				indic_bit = 0;
				__CHECK_BYTES(max_compressed_size, compressed_pos, sizeof(uint32_t));
				indic_pos = &compressed[compressed_pos];
				compressed_pos += sizeof(uint32_t);
			}
		} else {
			metadata_size = 0;
			match_len = best_len;
			__CHECK_BYTES(max_compressed_size, compressed_pos, sizeof(uint16_t));
			dest = (uint16_t *)&compressed[compressed_pos];

			match_len -= 3;
			best_offset -= 1;

			/* Classical meta-data */
			__CHECK_BYTES(max_compressed_size, compressed_pos, sizeof(uint16_t));
			metadata = (uint16_t)((best_offset << 3) | MIN(match_len, 7));
			PUSH_LE_U16(dest, metadata_size / sizeof(uint16_t), metadata);
			metadata_size += sizeof(uint16_t);

			if (match_len >= 7) {
				match_len -= 7;

				if (!nibble_index) {
					nibble_index = compressed_pos + metadata_size;

					__CHECK_BYTES(max_compressed_size, compressed_pos + metadata_size, sizeof(uint8_t));
					compressed[nibble_index] = MIN(match_len, 15);
					metadata_size += sizeof(uint8_t);
				} else {
					__CHECK_BYTES(max_compressed_size, nibble_index, sizeof(uint8_t));
					compressed[nibble_index] |= MIN(match_len, 15) << 4;
					nibble_index = 0;
				}

				if (match_len >= 15) {
					match_len -= 15;

					__CHECK_BYTES(max_compressed_size, compressed_pos + metadata_size, sizeof(uint8_t));
					compressed[compressed_pos + metadata_size] = MIN(match_len, 255);
					metadata_size += sizeof(uint8_t);

					if (match_len >= 255) {
						/* Additional match_len */

						match_len += 7 + 15;

						if (match_len < (1 << 16)) {
							__CHECK_BYTES(max_compressed_size, compressed_pos + metadata_size, sizeof(uint16_t));
							compressed[compressed_pos + metadata_size] = match_len & 0xFF;
							compressed[compressed_pos + metadata_size + 1] = (match_len >> 8);
							metadata_size += sizeof(uint16_t);
						} else {
							__CHECK_BYTES(max_compressed_size, compressed_pos + metadata_size, sizeof(uint16_t) + sizeof(uint32_t));
							compressed[compressed_pos + metadata_size] = 0;
							compressed[compressed_pos + metadata_size + 1] = 0;
							metadata_size += sizeof(uint16_t);

							compressed[compressed_pos + metadata_size] = match_len & 0xFF;
							compressed[compressed_pos + metadata_size + 1] = (match_len >> 8) & 0xFF;
							compressed[compressed_pos + metadata_size + 2] = (match_len >> 16) & 0xFF;
							compressed[compressed_pos + metadata_size + 3] = (match_len >> 24) & 0xFF;
							metadata_size += sizeof(uint32_t);
						}
					}
				}
			}

			indic = (indic << 1) | 1;
			indic_bit += 1;

			if (indic_bit == 32) {
				PUSH_LE_U32(indic_pos, 0, indic);
				indic_bit = 0;
				indic_pos = &compressed[compressed_pos];
				compressed_pos += sizeof(uint32_t);
			}

			compressed_pos += metadata_size;
			uncompressed_pos += best_len;
			byte_left -= best_len;
		}
	}

	indic <<= 32 - indic_bit;
	indic |= (1 << (32 - indic_bit)) - 1;
	PUSH_LE_U32(indic_pos, 0, indic);

	return compressed_pos;
}

ssize_t lzxpress_decompress(const uint8_t *input,
			    uint32_t input_size,
			    uint8_t *output,
			    uint32_t max_output_size)
{
	uint32_t output_index, input_index;
	uint32_t indicator, indicator_bit;
	uint32_t length;
	uint32_t offset;
	uint32_t nibble_index;
	uint32_t i;

	output_index = 0;
	input_index = 0;
	indicator = 0;
	indicator_bit = 0;
	length = 0;
	offset = 0;
	nibble_index = 0;

#define CHECK_INPUT_BYTES(__needed) \
	__CHECK_BYTES(input_size, input_index, __needed)
#define CHECK_OUTPUT_BYTES(__needed) \
	__CHECK_BYTES(max_output_size, output_index, __needed)

	do {
		if (indicator_bit == 0) {
			CHECK_INPUT_BYTES(sizeof(uint32_t));
			indicator = PULL_LE_U32(input, input_index);
			input_index += sizeof(uint32_t);
			indicator_bit = 32;
		}
		indicator_bit--;

		/*
		 * check whether the bit specified by indicator_bit is set or not
		 * set in indicator. For example, if indicator_bit has value 4
		 * check whether the 4th bit of the value in indicator is set
		 */
		if (((indicator >> indicator_bit) & 1) == 0) {
			CHECK_INPUT_BYTES(sizeof(uint8_t));
			CHECK_OUTPUT_BYTES(sizeof(uint8_t));
			output[output_index] = input[input_index];
			input_index += sizeof(uint8_t);
			output_index += sizeof(uint8_t);
		} else {
			CHECK_INPUT_BYTES(sizeof(uint16_t));
			length = PULL_LE_U16(input, input_index);
			input_index += sizeof(uint16_t);
			offset = (length / 8) + 1;
			length = length % 8;

			if (length == 7) {
				if (nibble_index == 0) {
					CHECK_INPUT_BYTES(sizeof(uint8_t));
					nibble_index = input_index;
					length = input[input_index] % 16;
					input_index += sizeof(uint8_t);
				} else {
					length = input[nibble_index] / 16;
					nibble_index = 0;
				}

				if (length == 15) {
					CHECK_INPUT_BYTES(sizeof(uint8_t));
					length = input[input_index];
					input_index += sizeof(uint8_t);
					if (length == 255) {
						CHECK_INPUT_BYTES(sizeof(uint16_t));
						length = PULL_LE_U16(input, input_index);
						input_index += sizeof(uint16_t);
						if (length == 0) {
							CHECK_INPUT_BYTES(sizeof(uint32_t));
							length = PULL_LE_U32(input, input_index);
							input_index += sizeof(uint32_t);
						}

						if (length < (15 + 7)) {
							return -1;
						}
						length -= (15 + 7);
					}
					length += 15;
				}
				length += 7;
			}
			length += 3;

			if (length == 0) {
				return -1;
			}

			for (i = 0; i < length; i++) {
				if (offset > output_index) {
					return -1;
				}
				CHECK_OUTPUT_BYTES(sizeof(uint8_t));
				output[output_index] = output[output_index - offset];
				output_index += sizeof(uint8_t);
			}
		}
	} while ((output_index < max_output_size) && (input_index < (input_size)));

	return output_index;
}
