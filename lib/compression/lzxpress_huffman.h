/*
 * Samba compression library - LGPLv3
 *
 * Copyright © Catalyst IT 2022
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

#ifndef HAVE_LZXPRESS_HUFFMAN_H
#define HAVE_LZXPRESS_HUFFMAN_H


struct huffman_node {
	struct huffman_node *left;
	struct huffman_node *right;
	uint32_t count;
	uint16_t symbol;
	int8_t depth;
};


/*
 * LZX_HUFF_COMP_HASH_BITS is how big to make the hash tables
 * (12 means 4096, etc).
 *
 * A larger number (up to 16) will be faster on long messages (fewer
 * collisions), but probably slower on short ones (more prep).
 */
#define LZX_HUFF_COMP_HASH_BITS 14


/*
 * This struct just coalesces all the memory you need for LZ77 + Huffman
 * compression together in one bundle.
 *
 * There are a few different things you want, you usually want them all, so
 * this makes it easy to allocate them all at once.
 */

struct lzxhuff_compressor_mem {
	struct huffman_node leaf_nodes[512];
	struct huffman_node internal_nodes[512];
	uint16_t symbol_values[512];
	uint16_t intermediate[65536 + 6];
	uint16_t hash_table1[1 << LZX_HUFF_COMP_HASH_BITS];
	uint16_t hash_table2[1 << LZX_HUFF_COMP_HASH_BITS];
};


ssize_t lzxpress_huffman_compress(struct lzxhuff_compressor_mem *cmp,
				  const uint8_t *input_bytes,
				  size_t input_size,
				  uint8_t *output,
				  size_t available_size);


ssize_t lzxpress_huffman_compress_talloc(TALLOC_CTX *mem_ctx,
					 const uint8_t *input_bytes,
					 size_t input_size,
					 uint8_t **output);

ssize_t lzxpress_huffman_decompress(const uint8_t *input,
				    size_t input_size,
				    uint8_t *output,
				    size_t max_output_size);

uint8_t *lzxpress_huffman_decompress_talloc(TALLOC_CTX *mem_ctx,
					    const uint8_t *input_bytes,
					    size_t input_size,
					    size_t output_size);

/*
 * lzxpress_huffman_max_compressed_size()
 *
 * Return the most bytes the compression can take, to allow
 * pre-allocation.
 */
size_t lzxpress_huffman_max_compressed_size(size_t input_size);


#endif /* HAVE_LZXPRESS_HUFFMAN_H */
