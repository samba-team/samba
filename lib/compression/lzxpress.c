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


/*
 * LZX_PLAIN_COMP_HASH_BITS determines how big the hash table for finding
 * matches will be.
 *
 * The window in which we look for matches is 8192 bytes. That means with
 * random data a value of 13 is getting close to no collisions, while a 12
 * will miss about half the possible matches. With compressible data there
 * will generally be fewer and less diverse entries, so collisions are rarer.
 *
 * In the testsuite, bith 12 and 13 give better compression than Windows, but
 * 12 is faster. 11 does not save time and costs accuracy. Thus we prefer 12.
 */
#define LZX_PLAIN_COMP_HASH_BITS 12
/*
 * LZX_PLAIN_COMP_HASH_SEARCH_ATTEMPTS is how far ahead to search in the
 * circular hash table for a match, before we give up. A bigger number will
 * generally lead to better but slower compression, but a stupidly big number
 * will just be worse.
 */
#define LZX_PLAIN_COMP_HASH_SEARCH_ATTEMPTS 5
#define HASH_MASK ((1 << LZX_PLAIN_COMP_HASH_BITS) - 1)

static inline uint16_t three_byte_hash(const uint8_t *bytes)
{
	uint16_t a = bytes[0];
	uint16_t b = bytes[1] ^ 0x2e;
	uint16_t c = bytes[2] ^ 0x55;
	uint16_t ca = c - a;
	uint16_t d = ((a + b) << 8) ^ (ca << 5) ^ (c + b) ^ (0xcab + a);
	return d & HASH_MASK;
}


static inline void store_match(uint32_t *hash_table,
			       uint16_t h,
			       uint32_t offset)
{
	int i;
	uint32_t o = hash_table[h];
	uint16_t h2;
	uint16_t worst_h;
	int worst_score;

	if (o >= offset) {
		/* there is nothing there yet */
		hash_table[h] = offset;
		return;
	}
	for (i = 1; i < LZX_PLAIN_COMP_HASH_SEARCH_ATTEMPTS; i++) {
		h2 = (h + i) & HASH_MASK;
		if (hash_table[h2] >= offset) {
			hash_table[h2] = offset;
			return;
		}
	}
	/*
	 * There are no slots, but we really want to store this, so we'll kick
	 * out the one with the longest distance.
	 */
	worst_h = h;
	worst_score = offset - o;
	for (i = 1; i < LZX_PLAIN_COMP_HASH_SEARCH_ATTEMPTS; i++) {
		int score;
		h2 = (h + i) & HASH_MASK;
		o = hash_table[h2];
		score = offset - o;
		if (score > worst_score) {
			worst_score = score;
			worst_h = h2;
		}
	}
	hash_table[worst_h] = offset;
}


struct match {
	const uint8_t *there;
	uint32_t length;
};


static inline struct match lookup_match(uint32_t *hash_table,
					uint16_t h,
					const uint8_t *data,
					uint32_t offset,
					size_t max_len)
{
	int i;
	uint32_t o;
	uint16_t h2;
	size_t len;
	const uint8_t *there = NULL;
	const uint8_t *here = data + offset;
	struct match best = {0};

	for (i = 0; i < LZX_PLAIN_COMP_HASH_SEARCH_ATTEMPTS; i++) {
		h2 = (h + i) & HASH_MASK;
		o = hash_table[h2];
		if (o >= offset) {
			/*
			 * Either this is 0xffffffff, or something is really
			 * wrong.
			 *
			 * In setting this, we would never have stepped over
			 * an 0xffffffff, so we won't now.
			 */
			break;
		}
		if (offset - o > 8192) {
			/* Too far away to use */
			continue;
		}
		there = data + o;
		/*
		 * When we already have a long match, we can try to avoid
		 * measuring out another long, but shorter match.
		 */
		if (best.length > 1000 &&
		    there[best.length - 1] != best.there[best.length - 1]) {
			continue;
		}

		for (len = 0;
		     len < max_len && here[len] == there[len];
		     len++) {
			/* counting */
		}
		if (len > 2) {
			if (len > best.length) {
				best.length = len;
				best.there = there;
			}
		}
	}
	return best;
}

struct write_context {
	uint8_t *compressed;
	uint32_t compressed_pos;
	uint32_t max_compressed_size;
	uint32_t indic;
	uint32_t indic_bit;
	uint32_t indic_pos;
	uint32_t nibble_index;
};


#define CHECK_INPUT_BYTES(__needed) \
	__CHECK_BYTES(uncompressed_size, uncompressed_pos, __needed)
#define CHECK_OUTPUT_BYTES(__needed) \
	__CHECK_BYTES(wc->max_compressed_size, wc->compressed_pos, __needed)


static inline ssize_t push_indicator_bit(struct write_context *wc, uint32_t bit)
{
	wc->indic = (wc->indic << 1) | bit;
	wc->indic_bit += 1;

	if (wc->indic_bit == 32) {
		PUSH_LE_U32(wc->compressed, wc->indic_pos, wc->indic);
		wc->indic_bit = 0;
		CHECK_OUTPUT_BYTES(sizeof(uint32_t));
		wc->indic_pos = wc->compressed_pos;
		wc->compressed_pos += sizeof(uint32_t);
	}
	return wc->indic_pos;
}


static ssize_t encode_match(struct write_context *wc,
			    struct match match,
			    const uint8_t *here)
{
	uint32_t match_len = match.length - 3;
	uint32_t best_offset = here - match.there - 1;
	uint16_t metadata;

	if (best_offset > 8191) {
		return -1;
	}

	CHECK_OUTPUT_BYTES(sizeof(uint16_t));
	metadata = (uint16_t)((best_offset << 3) | MIN(match_len, 7));
	PUSH_LE_U16(wc->compressed, wc->compressed_pos, metadata);
	wc->compressed_pos += sizeof(uint16_t);

	if (match_len >= 7) {
		match_len -= 7;

		if (wc->nibble_index == 0) {
			wc->nibble_index = wc->compressed_pos;

			CHECK_OUTPUT_BYTES(sizeof(uint8_t));
			wc->compressed[wc->nibble_index] = MIN(match_len, 15);
			wc->compressed_pos += sizeof(uint8_t);
		} else {
			wc->compressed[wc->nibble_index] |= MIN(match_len, 15) << 4;
			wc->nibble_index = 0;
		}

		if (match_len >= 15) {
			match_len -= 15;

			CHECK_OUTPUT_BYTES(sizeof(uint8_t));
			wc->compressed[wc->compressed_pos] = MIN(match_len, 255);
			wc->compressed_pos += sizeof(uint8_t);

			if (match_len >= 255) {
				/* Additional match_len */

				match_len += 7 + 15;

				if (match_len < (1 << 16)) {
					CHECK_OUTPUT_BYTES(sizeof(uint16_t));
					PUSH_LE_U16(wc->compressed, wc->compressed_pos,
						    match_len);
					wc->compressed_pos += sizeof(uint16_t);
				} else {
					CHECK_OUTPUT_BYTES(sizeof(uint16_t) +
							   sizeof(uint32_t));
					PUSH_LE_U16(wc->compressed,
						    wc->compressed_pos, 0);
					wc->compressed_pos += sizeof(uint16_t);

					PUSH_LE_U32(wc->compressed,
						    wc->compressed_pos,
						    match_len);
					wc->compressed_pos += sizeof(uint32_t);
				}
			}
		}
	}
	return push_indicator_bit(wc, 1);
}

#undef CHECK_OUTPUT_BYTES
#define CHECK_OUTPUT_BYTES(__needed) \
	__CHECK_BYTES(wc.max_compressed_size, wc.compressed_pos, __needed)


ssize_t lzxpress_compress(const uint8_t *uncompressed,
			  uint32_t uncompressed_size,
			  uint8_t *compressed,
			  uint32_t max_compressed_size)
{
	/*
	 * This is the algorithm in [MS-XCA] 2.3 "Plain LZ77 Compression".
	 *
	 * It avoids Huffman encoding by including literal bytes inline when a
	 * match is not found. Every so often it includes a uint32 bit map
	 * flagging which positions contain matches and which contain
	 * literals. The encoding of matches is of variable size, depending on
	 * the match length; they are always at least 16 bits long, and can
	 * implicitly use unused half-bytes from earlier in the stream.
	 */
	ssize_t ret;
	uint32_t uncompressed_pos;
	struct write_context wc = {
		.indic = 0,
		.indic_pos = 0,
		.indic_bit = 0,
		.nibble_index = 0,
		.compressed = compressed,
		.compressed_pos = 0,
		.max_compressed_size = max_compressed_size
	};
	uint32_t hash_table[1 << LZX_PLAIN_COMP_HASH_BITS];
	memset(hash_table, 0xff, sizeof(hash_table));

	if (!uncompressed_size) {
		return 0;
	}

	uncompressed_pos = 0;
	CHECK_OUTPUT_BYTES(sizeof(uint32_t));
	PUSH_LE_U32(wc.compressed, wc.compressed_pos, 0);
	wc.compressed_pos += sizeof(uint32_t);

	while ((uncompressed_pos < uncompressed_size) &&
	       (wc.compressed_pos < wc.max_compressed_size)) {

		/* maximum len we can encode into metadata */
		const uint32_t max_len = MIN(0xFFFF + 3,
					     uncompressed_size - uncompressed_pos);
		const uint8_t *here = uncompressed + uncompressed_pos;
		uint16_t h;
		struct match match = {0};

		if (max_len >= 3) {
			h = three_byte_hash(here);
			match = lookup_match(hash_table,
					     h,
					     uncompressed,
					     uncompressed_pos,
					     max_len);

			store_match(hash_table, h, uncompressed_pos);
		} else {
			match.there = NULL;
			match.length = 0;
		}

		if (match.there == NULL) {
			/*
			 * This is going to be a literal byte, which we flag
			 * by setting a bit in an indicator field somewhere
			 * earlier in the stream.
			 */
			CHECK_INPUT_BYTES(sizeof(uint8_t));
			CHECK_OUTPUT_BYTES(sizeof(uint8_t));
			wc.compressed[wc.compressed_pos++] = *here;
			uncompressed_pos++;

			ret = push_indicator_bit(&wc, 0);
			if (ret < 0) {
				return ret;
			}
		} else {
			ret = encode_match(&wc, match, here);
			if (ret < 0) {
				return ret;
			}
			uncompressed_pos += match.length;
		}
	}

	if (wc.indic_bit != 0) {
		wc.indic <<= 32 - wc.indic_bit;
	}
	wc.indic |= UINT32_MAX >> wc.indic_bit;
	PUSH_LE_U32(wc.compressed, wc.indic_pos, wc.indic);

	return wc.compressed_pos;
}

ssize_t lzxpress_decompress(const uint8_t *input,
			    uint32_t input_size,
			    uint8_t *output,
			    uint32_t max_output_size)
{
	/*
	 * This is the algorithm in [MS-XCA] 2.4 "Plain LZ77 Decompression
	 * Algorithm Details".
	 */
	uint32_t output_index, input_index;
	uint32_t indicator, indicator_bit;
	uint32_t nibble_index;

	if (input_size == 0) {
		return 0;
	}

	output_index = 0;
	input_index = 0;
	indicator = 0;
	indicator_bit = 0;
	nibble_index = 0;

#undef CHECK_INPUT_BYTES
#define CHECK_INPUT_BYTES(__needed) \
	__CHECK_BYTES(input_size, input_index, __needed)
#undef CHECK_OUTPUT_BYTES
#define CHECK_OUTPUT_BYTES(__needed) \
	__CHECK_BYTES(max_output_size, output_index, __needed)

	do {
		if (indicator_bit == 0) {
			CHECK_INPUT_BYTES(sizeof(uint32_t));
			indicator = PULL_LE_U32(input, input_index);
			input_index += sizeof(uint32_t);
			if (input_index == input_size) {
				/*
				 * The compressor left room for indicator
				 * flags for data that doesn't exist.
				 */
				break;
			}
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
			uint32_t length;
			uint32_t offset;

			CHECK_INPUT_BYTES(sizeof(uint16_t));
			length = PULL_LE_U16(input, input_index);
			input_index += sizeof(uint16_t);
			offset = (length >> 3) + 1;
			length &= 7;

			if (length == 7) {
				if (nibble_index == 0) {
					CHECK_INPUT_BYTES(sizeof(uint8_t));
					nibble_index = input_index;
					length = input[input_index] & 0xf;
					input_index += sizeof(uint8_t);
				} else {
					length = input[nibble_index] >> 4;
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

			for (; length > 0; --length) {
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
