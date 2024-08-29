/*
 * Samba compression library - LGPLv3
 *
 * Copyright © Catalyst IT 2022
 *
 * Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
 *        and Jennifer Sutton <jennifersutton@catalyst.net.nz>
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
#include "lib/util/debug.h"
#include "lib/util/byteorder.h"
#include "lib/util/bytearray.h"

/*
 * DEBUG_NO_LZ77_MATCHES toggles the encoding of matches as matches. If it is
 * false the potential match is written as a series of literals, which is a
 * valid but usually inefficient encoding. This is useful for isolating a
 * problem to either the LZ77 or the Huffman stage.
 */
#ifndef DEBUG_NO_LZ77_MATCHES
#define DEBUG_NO_LZ77_MATCHES false
#endif

/*
 * DEBUG_HUFFMAN_TREE forces the drawing of ascii art huffman trees during
 * compression and decompression.
 *
 * These trees will also be drawn at DEBUG level 10, but that doesn't work
 * with cmocka tests.
 */
#ifndef DEBUG_HUFFMAN_TREE
#define DEBUG_HUFFMAN_TREE false
#endif

#if DEBUG_HUFFMAN_TREE
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) DBG_INFO(__VA_ARGS__)
#endif


#define LZXPRESS_ERROR -1LL

/*
 * We won't encode a match length longer than MAX_MATCH_LENGTH.
 *
 * Reports are that Windows has a limit at 64M.
 */
#define MAX_MATCH_LENGTH (64 * 1024 * 1024)


struct bitstream {
	const uint8_t *bytes;
	size_t byte_pos;
	size_t byte_size;
	uint32_t bits;
	int remaining_bits;
	uint16_t *table;
};


#if ! defined __has_builtin
#define __has_builtin(x) 0
#endif

/*
 * bitlen_nonzero_16() returns the bit number of the most significant bit, or
 * put another way, the integer log base 2. Log(0) is undefined; the argument
 * has to be non-zero!
 * 1     -> 0
 * 2,3   -> 1
 * 4-7   -> 2
 * 1024  -> 10, etc
 *
 * Probably this is handled by a compiler intrinsic function that maps to a
 * dedicated machine instruction.
 */

static inline int bitlen_nonzero_16(uint16_t x)
{
#if  __has_builtin(__builtin_clz)

	/* __builtin_clz returns the number of leading zeros */
	return (sizeof(unsigned int) * CHAR_BIT) - 1
		- __builtin_clz((unsigned int) x);

#else

	int count = -1;
	while(x) {
		x >>= 1;
		count++;
	}
	return count;

#endif
}


struct lzxhuff_compressor_context {
	const uint8_t *input_bytes;
	size_t input_size;
	size_t input_pos;
	size_t prev_block_pos;
	uint8_t *output;
	size_t available_size;
	size_t output_pos;
};

static int compare_huffman_node_count(struct huffman_node *a,
				      struct huffman_node *b)
{
	return a->count - b->count;
}

static int compare_huffman_node_depth(struct huffman_node *a,
				      struct huffman_node *b)
{
	int c = a->depth - b->depth;
	if (c != 0) {
		return c;
	}
	return (int)a->symbol - (int)b->symbol;
}


#define HASH_MASK ((1 << LZX_HUFF_COMP_HASH_BITS) - 1)

static inline uint16_t three_byte_hash(const uint8_t *bytes)
{
	/*
	 * MS-XCA says "three byte hash", but does not specify it.
	 *
	 * This one is just cobbled together, but has quite good distribution
	 * in the 12-14 bit forms, which is what we care about most.
	 * e.g: 13 bit: median 2048, min 2022, max 2074, stddev 6.0
	 */
	uint16_t a = bytes[0];
	uint16_t b = bytes[1] ^ 0x2e;
	uint16_t c = bytes[2] ^ 0x55;
	uint16_t ca = c - a;
	uint16_t d = ((a + b) << 8) ^ (ca << 5) ^ (c + b) ^ (0xcab + a);
	return d & HASH_MASK;
}


static inline uint16_t encode_match(size_t len, size_t offset)
{
	uint16_t code = 256;
	code |= MIN(len - 3, 15);
	code |= bitlen_nonzero_16(offset) << 4;
	return code;
}

/*
 * debug_huffman_tree() uses debug_huffman_tree_print() to draw the Huffman
 * tree in ascii art.
 *
 * Note that the Huffman tree is probably not the same as that implied by the
 * canonical Huffman encoding that is finally used. That tree would be the
 * same shape, but with the left and right toggled to sort the branches by
 * length, after which the symbols for each length sorted by value.
 */

static void debug_huffman_tree_print(struct huffman_node *node,
				     int *trail, int depth)
{
	if (node->left == NULL) {
		/* time to print a row */
		int j;
		bool branched = false;
		int row[17];
		char c[100];
		int s = node->symbol;
		char code[17];
		if (depth > 15) {
			fprintf(stderr,
				" \033[1;31m Max depth exceeded! (%d)\033[0m "
				" symbol %#3x claimed depth %d count %d\n",
				depth, node->symbol, node->depth, node->count);
			return;
		}
		for (j = depth - 1; j >= 0; j--) {
			if (branched) {
				if (trail[j] == -1) {
					row[j] = -3;
				} else {
					row[j] = -2;
				}
			} else if (trail[j] == -1) {
				row[j] = -1;
				branched = true;
			} else {
				row[j] = trail[j];
			}
		}
		for (j = 0; j < depth; j++) {
			switch (row[j]) {
			case -3:
				code[j] = '1';
				fprintf(stderr, "        ");
				break;
			case -2:
				code[j] = '0';
				fprintf(stderr, "      │ ");
				break;
			case -1:
				code[j] = '1';
				fprintf(stderr, "      ╰─");
				break;
			default:
				code[j] = '0';
				fprintf(stderr, "%5d─┬─", row[j]);
				break;
			}
		}
		code[depth] = 0;
		if (s < 32) {
			snprintf(c, sizeof(c),
				"\033[1;32m%02x\033[0m \033[1;33m%c%c%c\033[0m",
				 s,
				 0xE2, 0x90, 0x80 + s); /* utf-8 for symbol */
		}  else if (s < 127) {
			snprintf(c, sizeof(c),
				 "\033[1;32m%2x\033[0m '\033[10;32m%c\033[0m'",
				 s, s);
		} else if (s < 256) {
			snprintf(c, sizeof(c), "\033[1;32m%2x\033[0m", s);
		} else {
			uint16_t len = (s & 15) + 3;
			uint16_t dbits = ((s >> 4) & 15) + 1;
			snprintf(c, sizeof(c),
				 " \033[0;33mlen:%2d%s, "
				 "dist:%d-%d \033[0m \033[1;32m%3x\033[0m%s",
				 len,
				 len == 18 ? "+" : "",
				 1 << (dbits - 1),
				 (1 << dbits) - 1,
				 s,
				 s == 256 ? " \033[1;31mEOF\033[0m" : "");

		}

		fprintf(stderr, "──%5d %s \033[2;37m%s\033[0m\n",
			node->count, c, code);
		return;
	}
	trail[depth] = node->count;
	debug_huffman_tree_print(node->left, trail, depth + 1);
	trail[depth] = -1;
	debug_huffman_tree_print(node->right, trail, depth + 1);
}


/*
 * If DEBUG_HUFFMAN_TREE is defined true, debug_huffman_tree()
 * will print a tree looking something like this:
 *
 *     7─┬───    3  len:18+, dist:1-1  10f 0
 *       ╰─    4─┬─    2─┬───    1 61 'a' 100
 *               │       ╰───    1 62 'b' 101
 *               ╰─    2─┬───    1 63 'c' 110
 *                       ╰───    1  len: 3, dist:1-1  100 EOF 111
 *
 * This is based off a Huffman root node, and the tree may not be the same as
 * the canonical tree.
 */
static void debug_huffman_tree(struct huffman_node *root)
{
	int trail[17];
	debug_huffman_tree_print(root, trail, 0);
}


/*
 * If DEBUG_HUFFMAN_TREE is defined true, debug_huffman_tree_from_table()
 * will print something like this based on a decoding symbol table.
 *
 *  Tree from decoding table 9 nodes → 5 codes
 * 10000─┬─── 5000  len:18+, dist:1-1  10f 0
 *       ╰─ 5000─┬─ 2500─┬─── 1250 61 'a' 100
 *               │       ╰─── 1250 62 'b' 101
 *               ╰─ 2500─┬─── 1250 63 'c' 110
 *                       ╰─── 1250  len: 3, dist:1-1  100 EOF 111
 *
 * This is the canonical form of the Huffman tree where the actual counts
 * aren't known (we use "10000" to help indicate relative frequencies).
 */
static void debug_huffman_tree_from_table(uint16_t *table)
{
	int trail[17];
	struct huffman_node nodes[1024] = {{0}};
	uint16_t codes[1024];
	size_t n = 1;
	size_t i = 0;
	codes[0] = 0;
	nodes[0].count = 10000;

	while (i < n) {
		uint16_t index = codes[i];
		struct huffman_node *node = &nodes[i];
		if (table[index] == 0xffff) {
			/* internal node */
			index <<= 1;
			/* left */
			index++;
			codes[n] = index;
			node->left = nodes + n;
			nodes[n].count = node->count >> 1;
			n++;
			/*right*/
			index++;
			codes[n] = index;
			node->right = nodes + n;
			nodes[n].count = node->count >> 1;
			n++;
		} else {
			/* leaf node */
			node->symbol = table[index] & 511;
		}
		i++;
	}

	fprintf(stderr,
		"\033[1;34m Tree from decoding table\033[0m "
		"%zu nodes → %zu codes\n",
		n, (n + 1) / 2);
	debug_huffman_tree_print(nodes, trail, 0);
}


static bool depth_walk(struct huffman_node *n, uint32_t depth)
{
	bool ok;
	if (n->left == NULL) {
		/* this is a leaf, record the depth */
		n->depth = depth;
		return true;
	}
	if (depth > 14) {
		return false;
	}
	ok = (depth_walk(n->left, depth + 1) &&
	      depth_walk(n->right, depth + 1));

	return ok;
}


static bool check_and_record_depths(struct huffman_node *root)
{
	return depth_walk(root, 0);
}


static bool encode_values(struct huffman_node *leaves,
			  size_t n_leaves,
			  uint16_t symbol_values[512])
{
	size_t i;
	/*
	 * See, we have a leading 1 in our internal code representation, which
	 * indicates the code length.
	 */
	uint32_t code = 1;
	uint32_t code_len = 0;
	memset(symbol_values, 0, sizeof(uint16_t) * 512);
	for (i = 0; i < n_leaves; i++) {
		code <<= leaves[i].depth - code_len;
		code_len = leaves[i].depth;

		symbol_values[leaves[i].symbol] = code;
		code++;
	}
	/*
	 * The last code should be 11111... with code_len + 1 ones. The final
	 * code++ will wrap this round to 1000... with code_len + 1 zeroes.
	 */

	if (code != 2 << code_len) {
		return false;
	}
	return true;
}


static int generate_huffman_codes(struct huffman_node *leaf_nodes,
				  struct huffman_node *internal_nodes,
				  uint16_t symbol_values[512])
{
	size_t head_leaf = 0;
	size_t head_branch = 0;
	size_t tail_branch = 0;
	struct huffman_node *huffman_root = NULL;
	size_t i, j;
	size_t n_leaves = 0;

	/*
	 * Before we sort the nodes, we can eliminate the unused ones.
	 */
	for (i = 0; i < 512; i++) {
		if (leaf_nodes[i].count) {
			leaf_nodes[n_leaves] = leaf_nodes[i];
			n_leaves++;
		}
	}
	if (n_leaves == 0) {
		return LZXPRESS_ERROR;
	}
	if (n_leaves == 1) {
		/*
		 * There is *almost* no way this should happen, and it would
		 * ruin the tree (because the shortest possible codes are 1
		 * bit long, and there are two of them).
		 *
		 * The only way to get here is in an internal block in a
		 * 3-or-more block message (i.e. > 128k), which consists
		 * entirely of a match starting in the previous block (if it
		 * was the end block, it would have the EOF symbol).
		 *
		 * What we do is add a dummy symbol which is this one XOR 256.
		 * It won't be used in the stream but will balance the tree.
		 */
		leaf_nodes[1] = leaf_nodes[0];
		leaf_nodes[1].symbol ^= 0x100;
		n_leaves = 2;
	}

	/* note, in sort we're using internal_nodes as auxiliary space */
	stable_sort(leaf_nodes,
		    internal_nodes,
		    n_leaves,
		    sizeof(struct huffman_node),
		    (samba_compare_fn_t)compare_huffman_node_count);

	/*
	 * This outer loop is for re-quantizing the counts if the tree is too
	 * tall (>15), which we need to do because the final encoding can't
	 * express a tree that deep.
	 *
	 * In theory, this should be a 'while (true)' loop, but we chicken
	 * out with 10 iterations, just in case.
	 *
	 * In practice it will almost always resolve in the first round; if
	 * not then, in the second or third. Remember we'll looking at 64k or
	 * less, so the rarest we can have is 1 in 64k; each round of
	 * quantization effectively doubles its frequency to 1 in 32k, 1 in
	 * 16k, etc, until we're treating the rare symbol as actually quite
	 * common.
	 */
	for (j = 0; j < 10; j++) {
		bool less_than_15_bits;
		while (true) {
			struct huffman_node *a = NULL;
			struct huffman_node *b = NULL;
			size_t leaf_len = n_leaves - head_leaf;
			size_t internal_len = tail_branch - head_branch;

			if (leaf_len + internal_len == 1) {
				/*
				 * We have the complete tree. The root will be
				 * an internal node unless there is just one
				 * symbol, which is already impossible.
				 */
				if (unlikely(leaf_len == 1)) {
					return LZXPRESS_ERROR;
				} else {
					huffman_root = \
						&internal_nodes[head_branch];
				}
				break;
			}
			/*
			 * We know here we have at least two nodes, and we
			 * want to select the two lowest scoring ones. Those
			 * have to be either a) the head of each queue, or b)
			 * the first two nodes of either queue.
			 *
			 * The complicating factors are: a) we need to check
			 * the length of each queue, and b) in the case of
			 * ties, we prefer to pair leaves with leaves.
			 *
			 * Note a complication we don't have: the leaf node
			 * queue never grows, and the subtree queue starts
			 * empty and cannot grow beyond n - 1. It feeds on
			 * itself. We don't need to think about overflow.
			 */
			if (leaf_len == 0) {
				/* two from subtrees */
				a = &internal_nodes[head_branch];
				b = &internal_nodes[head_branch + 1];
				head_branch += 2;
			} else if (internal_len == 0) {
				/* two from nodes */
				a = &leaf_nodes[head_leaf];
				b = &leaf_nodes[head_leaf + 1];
				head_leaf += 2;
			} else if (leaf_len == 1 && internal_len == 1) {
				/* one of each */
				a = &leaf_nodes[head_leaf];
				b = &internal_nodes[head_branch];
				head_branch++;
				head_leaf++;
			} else {
				/*
				 * Take the lowest head, twice, checking for
				 * length after taking the first one.
				 */
				if (leaf_nodes[head_leaf].count >
				    internal_nodes[head_branch].count) {
					a = &internal_nodes[head_branch];
					head_branch++;
					if (internal_len == 1) {
						b = &leaf_nodes[head_leaf];
						head_leaf++;
						goto done;
					}
				} else {
					a = &leaf_nodes[head_leaf];
					head_leaf++;
					if (leaf_len == 1) {
						b = &internal_nodes[head_branch];
						head_branch++;
						goto done;
					}
				}
				/* the other node */
				if (leaf_nodes[head_leaf].count >
				    internal_nodes[head_branch].count) {
					b = &internal_nodes[head_branch];
					head_branch++;
				} else {
					b = &leaf_nodes[head_leaf];
					head_leaf++;
				}
			}
		done:
			/*
			 * Now we add a new node to the subtrees list that
			 * combines the score of node_a and node_b, and points
			 * to them as children.
			 */
			internal_nodes[tail_branch].count = a->count + b->count;
			internal_nodes[tail_branch].left = a;
			internal_nodes[tail_branch].right = b;
			tail_branch++;
			if (tail_branch == n_leaves) {
				/*
				 * We're not getting here, no way, never ever.
				 * Unless we made a terrible mistake.
				 *
				 * That is, in a binary tree with n leaves,
				 * there are ALWAYS n-1 internal nodes.
				 */
				return LZXPRESS_ERROR;
			}
		}
		if (CHECK_DEBUGLVL(10) || DEBUG_HUFFMAN_TREE) {
			debug_huffman_tree(huffman_root);
		}
		/*
		 * We have a tree, and need to turn it into a lookup table,
		 * and see if it is shallow enough (<= 15).
		 */
		less_than_15_bits = check_and_record_depths(huffman_root);
		if (less_than_15_bits) {
			/*
			 * Now the leaf nodes know how deep they are, and we
			 * no longer need the internal nodes.
			 *
			 * We need to sort the nodes of equal depth, so that
			 * they are sorted by depth first, and symbol value
			 * second. The internal_nodes can again be auxiliary
			 * memory.
			 */
			stable_sort(
				leaf_nodes,
				internal_nodes,
				n_leaves,
				sizeof(struct huffman_node),
				(samba_compare_fn_t)compare_huffman_node_depth);

			encode_values(leaf_nodes, n_leaves, symbol_values);

			return n_leaves;
		}

		/*
		 * requantize by halving and rounding up, so that small counts
		 * become relatively bigger. This will lead to a flatter tree.
		 */
		for (i = 0; i < n_leaves; i++) {
			leaf_nodes[i].count >>= 1;
			leaf_nodes[i].count += 1;
		}
		head_leaf = 0;
		head_branch = 0;
		tail_branch = 0;
	}
	return LZXPRESS_ERROR;
}

/*
 * LZX_HUFF_COMP_HASH_SEARCH_ATTEMPTS is how far ahead to search in the
 * circular hash table for a match, before we give up. A bigger number will
 * generally lead to better but slower compression, but a stupidly big number
 * will just be worse.
 *
 * If you're fiddling with this, consider also fiddling with
 * LZX_HUFF_COMP_HASH_BITS.
 */
#define LZX_HUFF_COMP_HASH_SEARCH_ATTEMPTS 5

static inline void store_match(uint16_t *hash_table,
			       uint16_t h,
			       uint16_t offset)
{
	int i;
	uint16_t o = hash_table[h];
	uint16_t h2;
	uint16_t worst_h;
	int worst_score;

	if (o == 0xffff) {
		/* there is nothing there yet */
		hash_table[h] = offset;
		return;
	}
	for (i = 1; i < LZX_HUFF_COMP_HASH_SEARCH_ATTEMPTS; i++) {
		h2 = (h + i) & HASH_MASK;
		if (hash_table[h2] == 0xffff) {
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
	for (i = 1; i < LZX_HUFF_COMP_HASH_SEARCH_ATTEMPTS; i++) {
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


/*
 * Yes, struct match looks a lot like a DATA_BLOB.
 */
struct match {
	const uint8_t *there;
	size_t length;
};


static inline struct match lookup_match(uint16_t *hash_table,
					uint16_t h,
					const uint8_t *data,
					const uint8_t *here,
					size_t max_len)
{
	int i;
	uint16_t o = hash_table[h];
	uint16_t h2;
	size_t len;
	const uint8_t *there = NULL;
	struct match best = {0};

	for (i = 0; i < LZX_HUFF_COMP_HASH_SEARCH_ATTEMPTS; i++) {
		h2 = (h + i) & HASH_MASK;
		o = hash_table[h2];
		if (o == 0xffff) {
			/*
			 * in setting this, we would never have stepped over
			 * an 0xffff, so we won't now.
			 */
			break;
		}
		there = data + o;
		if (here - there > 65534 || there > here) {
			continue;
		}

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
			/*
			 * As a tiebreaker, we prefer the closer match which
			 * is likely to encode smaller (and certainly no worse).
			 */
			if (len > best.length ||
			    (len == best.length && there > best.there)) {
				best.length = len;
				best.there = there;
			}
		}
	}
	return best;
}



static ssize_t lz77_encode_block(struct lzxhuff_compressor_context *cmp_ctx,
				 struct lzxhuff_compressor_mem *cmp_mem,
				 uint16_t *hash_table,
				 uint16_t *prev_hash_table)
{
	uint16_t *intermediate = cmp_mem->intermediate;
	struct huffman_node *leaf_nodes = cmp_mem->leaf_nodes;
	uint16_t *symbol_values = cmp_mem->symbol_values;
	size_t i, j, intermediate_len;
	const uint8_t *data = cmp_ctx->input_bytes + cmp_ctx->input_pos;
	const uint8_t *prev_block = NULL;
	size_t remaining_size = cmp_ctx->input_size - cmp_ctx->input_pos;
	size_t block_end = MIN(65536, remaining_size);
	struct match match;
	int n_symbols;

	if (cmp_ctx->input_size < cmp_ctx->input_pos) {
		return LZXPRESS_ERROR;
	}

	if (cmp_ctx->prev_block_pos != cmp_ctx->input_pos) {
		prev_block = cmp_ctx->input_bytes + cmp_ctx->prev_block_pos;
	} else if (prev_hash_table != NULL) {
		/* we've got confused! hash and block should go together */
		return LZXPRESS_ERROR;
	}

	/*
	 * leaf_nodes is used to count the symbols seen, for later Huffman
	 * encoding.
	 */
	for (i = 0; i < 512; i++) {
		leaf_nodes[i] = (struct huffman_node) {
			.symbol = i
		};
	}

	j = 0;

	if (remaining_size < 41 || DEBUG_NO_LZ77_MATCHES) {
		/*
		 * There is no point doing a hash table and looking for
		 * matches in this tiny block (remembering we are committed to
		 * using 32 bits, so there's a good chance we wouldn't even
		 * save a byte). The threshold of 41 matches Windows.
		 * If remaining_size < 3, we *can't* do the hash.
		 */
		i = 0;
	} else {
		/*
		 * We use 0xffff as the unset value for table, because it is
		 * not a valid match offset (and 0x0 is).
		 */
		memset(hash_table, 0xff, sizeof(cmp_mem->hash_table1));

		for (i = 0; i <= block_end - 3; i++) {
			uint16_t code;
			const uint8_t *here = data + i;
			uint16_t h = three_byte_hash(here);
			size_t max_len = MIN(remaining_size - i, MAX_MATCH_LENGTH);
			match = lookup_match(hash_table,
					     h,
					     data,
					     here,
					     max_len);

			if (match.there == NULL && prev_hash_table != NULL) {
				/*
				 * If this is not the first block,
				 * backreferences can look into the previous
				 * block (but only as far as 65535 bytes, so
				 * the end of this block cannot see the start
				 * of the last one).
				 */
				match = lookup_match(prev_hash_table,
						     h,
						     prev_block,
						     here,
						     remaining_size - i);
			}

			store_match(hash_table, h, i);

			if (match.there == NULL) {
				/* add a literal and move on. */
				uint8_t c = data[i];
				leaf_nodes[c].count++;
				intermediate[j] = c;
				j++;
				continue;
			}

			/* a real match */
			if (match.length <= 65538) {
				intermediate[j] = 0xffff;
				intermediate[j + 1] = match.length - 3;
				intermediate[j + 2] = here - match.there;
				j += 3;
			} else {
				size_t m = match.length - 3;
				intermediate[j] = 0xfffe;
				intermediate[j + 1] = m & 0xffff;
				intermediate[j + 2] = m >> 16;
				intermediate[j + 3] = here - match.there;
				j += 4;
			}
			code = encode_match(match.length, here - match.there);
			leaf_nodes[code].count++;
			i += match.length - 1; /* `- 1` for the loop i++ */
			/*
			 * A match can take us past the intended block length,
			 * extending the block. We don't need to do anything
			 * special for this case -- the loops will naturally
			 * do the right thing.
			 */
		}
	}

	/*
	 * There might be some bytes at the end.
	 */
	for (; i < block_end; i++) {
		leaf_nodes[data[i]].count++;
		intermediate[j] = data[i];
		j++;
	}

	if (i == remaining_size) {
		/* add a trailing EOF marker (256) */
		intermediate[j] = 0xffff;
		intermediate[j + 1] = 0;
		intermediate[j + 2] = 1;
		j += 3;
		leaf_nodes[256].count++;
	}

	intermediate_len = j;

	cmp_ctx->prev_block_pos = cmp_ctx->input_pos;
	cmp_ctx->input_pos += i;

	/* fill in the symbols table */
	n_symbols = generate_huffman_codes(leaf_nodes,
					   cmp_mem->internal_nodes,
					   symbol_values);
	if (n_symbols < 0) {
		return n_symbols;
	}

	return intermediate_len;
}



static ssize_t write_huffman_table(uint16_t symbol_values[512],
				   uint8_t *output,
				   size_t available_size)
{
	size_t i;

	if (available_size < 256) {
		return LZXPRESS_ERROR;
	}

	for (i = 0; i < 256; i++) {
		uint8_t b = 0;
		uint16_t even = symbol_values[i * 2];
		uint16_t odd = symbol_values[i * 2 + 1];
		if (even != 0) {
			b = bitlen_nonzero_16(even);
		}
		if (odd != 0) {
			b |= bitlen_nonzero_16(odd) << 4;
		}
		output[i] = b;
	}
	return i;
}


struct write_context {
	uint8_t *dest;
	size_t dest_len;
	size_t head;                 /* where lengths go */
	size_t next_code;            /* where symbol stream goes */
	size_t pending_next_code;    /* will be next_code */
	unsigned bit_len;
	uint32_t bits;
};

/*
 * Write out 16 bits, little-endian, for write_huffman_codes()
 *
 * As you'll notice, there's a bit to do.
 *
 * We are collecting up bits in a uint32_t, then when there are 16 of them we
 * write out a word into the stream, using a trio of offsets (wc->next_code,
 * wc->pending_next_code, and wc->head) which dance around ensuring that the
 * bitstream and the interspersed lengths are in the right places relative to
 * each other.
 */

static inline bool write_bits(struct write_context *wc,
			      uint16_t code, uint16_t length)
{
	wc->bits <<= length;
	wc->bits |= code;
	wc->bit_len += length;
	if (wc->bit_len > 16) {
		uint32_t w = wc->bits >> (wc->bit_len - 16);
		wc->bit_len -= 16;
		if (wc->next_code + 2 > wc->dest_len ||
		    unlikely(wc->bit_len > 16)) {
			return false;
		}
		wc->dest[wc->next_code] = w & 0xff;
		wc->dest[wc->next_code + 1] = (w >> 8) & 0xff;
		wc->next_code = wc->pending_next_code;
		wc->pending_next_code = wc->head;
		wc->head += 2;
	}
	return true;
}


static inline bool write_code(struct write_context *wc, uint16_t code)
{
	int code_bit_len = bitlen_nonzero_16(code);
	if (unlikely(code == 0)) {
		return false;
	}
	code &= (1 << code_bit_len) - 1;
	return  write_bits(wc, code, code_bit_len);
}

static inline bool write_byte(struct write_context *wc, uint8_t byte)
{
	if (wc->head + 1 > wc->dest_len) {
		return false;
	}
	wc->dest[wc->head] = byte;
	wc->head++;
	return true;
}


static inline bool write_long_len(struct write_context *wc, size_t len)
{
	if (len < 65535) {
		if (wc->head + 3 > wc->dest_len) {
			return false;
		}
		wc->dest[wc->head] = 255;
		wc->dest[wc->head + 1] = len & 255;
		wc->dest[wc->head + 2] = len >> 8;
		wc->head += 3;
	} else {
		if (wc->head + 7 > wc->dest_len) {
			return false;
		}
		wc->dest[wc->head] = 255;
		wc->dest[wc->head + 1] = 0;
		wc->dest[wc->head + 2] = 0;
		wc->dest[wc->head + 3] = len & 255;
		wc->dest[wc->head + 4] = (len >> 8) & 255;
		wc->dest[wc->head + 5] = (len >> 16) & 255;
		wc->dest[wc->head + 6] = (len >> 24) & 255;
		wc->head += 7;
	}
	return true;
}

static ssize_t write_compressed_bytes(uint16_t symbol_values[512],
				      uint16_t *intermediate,
				      size_t intermediate_len,
				      uint8_t *dest,
				      size_t dest_len)
{
	bool ok;
	size_t i;
	size_t end;
	struct write_context wc = {
		.head = 4,
		.pending_next_code = 2,
		.dest = dest,
		.dest_len = dest_len
	};
	for (i = 0; i < intermediate_len; i++) {
		uint16_t c = intermediate[i];
		size_t len;
		uint16_t distance;
		uint16_t code_len = 0;
		uint16_t code_dist = 0;
		if (c < 256) {
			ok = write_code(&wc, symbol_values[c]);
			if (!ok) {
				return LZXPRESS_ERROR;
			}
			continue;
		}

		if (c == 0xfffe) {
			if (i > intermediate_len - 4) {
				return LZXPRESS_ERROR;
			}

			len = intermediate[i + 1];
			len |= (uint32_t)intermediate[i + 2] << 16;
			distance = intermediate[i + 3];
			i += 3;
		} else if (c == 0xffff) {
			if (i > intermediate_len - 3) {
				return LZXPRESS_ERROR;
			}
			len = intermediate[i + 1];
			distance = intermediate[i + 2];
			i += 2;
		} else {
			return LZXPRESS_ERROR;
		}
		if (unlikely(distance == 0)) {
			return LZXPRESS_ERROR;
		}
		/* len has already had 3 subtracted */
		if (len >= 15) {
			/*
			 * We are going to need to write extra length
			 * bytes into the stream, but we don't do it
			 * now, we do it after the code has been
			 * written (and before the distance bits).
			 */
			code_len = 15;
		} else {
			code_len = len;
		}
		code_dist = bitlen_nonzero_16(distance);
		c = 256 | (code_dist << 4) | code_len;
		if (c > 511) {
			return LZXPRESS_ERROR;
		}

		ok = write_code(&wc, symbol_values[c]);
		if (!ok) {
			return LZXPRESS_ERROR;
		}

		if (code_len == 15) {
			if (len >= 270) {
				ok = write_long_len(&wc, len);
			} else {
				ok = write_byte(&wc, len - 15);
			}
			if (! ok) {
				return LZXPRESS_ERROR;
			}
		}
		if (code_dist != 0) {
			uint16_t dist_bits = distance - (1 << code_dist);
			ok = write_bits(&wc, dist_bits, code_dist);
			if (!ok) {
				return LZXPRESS_ERROR;
			}
		}
	}
	/*
	 * There are some intricacies around flushing the bits and returning
	 * the length.
	 *
	 * If the returned length is not exactly right and there is another
	 * block, that block will read its huffman table from the wrong place,
	 * and have all the symbol codes out by a multiple of 4.
	 */
	end = wc.head;
	if (wc.bit_len == 0) {
		end -= 2;
	}
	ok = write_bits(&wc, 0, 16 - wc.bit_len);
	if (!ok) {
		return LZXPRESS_ERROR;
	}
	for (i = 0; i < 2; i++) {
		/*
		 * Flush out the bits with zeroes. It doesn't matter if we do
		 * a round too many, as we have buffer space, and have already
		 * determined the returned length (end).
		 */
		ok = write_bits(&wc, 0, 16);
		if (!ok) {
			return LZXPRESS_ERROR;
		}
	}
	return end;
}


static ssize_t lzx_huffman_compress_block(struct lzxhuff_compressor_context *cmp_ctx,
					  struct lzxhuff_compressor_mem *cmp_mem,
					  size_t block_no)
{
	ssize_t intermediate_size;
	uint16_t *hash_table = NULL;
	uint16_t *back_window_hash_table = NULL;
	ssize_t bytes_written;

	if (cmp_ctx->available_size - cmp_ctx->output_pos < 260) {
		/* huffman block + 4 bytes */
		return LZXPRESS_ERROR;
	}

	/*
	 * For LZ77 compression, we keep a hash table for the previous block,
	 * via alternation after the first block.
	 *
	 * LZ77 writes into the intermediate buffer in the cmp_mem context.
	 */
	if (block_no == 0) {
		hash_table = cmp_mem->hash_table1;
		back_window_hash_table = NULL;
	} else if (block_no & 1) {
		hash_table = cmp_mem->hash_table2;
		back_window_hash_table = cmp_mem->hash_table1;
	} else {
		hash_table = cmp_mem->hash_table1;
		back_window_hash_table = cmp_mem->hash_table2;
	}

	intermediate_size = lz77_encode_block(cmp_ctx,
					      cmp_mem,
					      hash_table,
					      back_window_hash_table);

	if (intermediate_size < 0) {
		return intermediate_size;
	}

	/*
	 * Write the 256 byte Huffman table, based on the counts gained in
	 * LZ77 phase.
	 */
	bytes_written = write_huffman_table(
		cmp_mem->symbol_values,
		cmp_ctx->output + cmp_ctx->output_pos,
		cmp_ctx->available_size - cmp_ctx->output_pos);

	if (bytes_written != 256) {
		return LZXPRESS_ERROR;
	}
	cmp_ctx->output_pos += 256;

	/*
	 * Write the compressed bytes using the LZ77 matches and Huffman codes
	 * worked out in the previous steps.
	 */
	bytes_written = write_compressed_bytes(
		cmp_mem->symbol_values,
		cmp_mem->intermediate,
		intermediate_size,
		cmp_ctx->output + cmp_ctx->output_pos,
		cmp_ctx->available_size - cmp_ctx->output_pos);

	if (bytes_written < 0) {
		return bytes_written;
	}

	cmp_ctx->output_pos += bytes_written;
	return bytes_written;
}

/*
 * lzxpress_huffman_max_compressed_size()
 *
 * Return the most bytes the compression can take, to allow
 * pre-allocation.
 */
size_t lzxpress_huffman_max_compressed_size(size_t input_size)
{
	/*
	 * In the worst case, the output size should be about the same as the
	 * input size, plus the 256 byte header per 64k block. We aim for
	 * ample, but within the order of magnitude.
	 */
	return input_size + (input_size / 8) + 270;
}

/*
 * lzxpress_huffman_compress_talloc()
 *
 * This is the convenience function that allocates the compressor context and
 * output memory for you. The return value is the number of bytes written to
 * the location indicated by the output pointer.
 *
 * The maximum input_size is effectively around 227MB due to the need to guess
 * an upper bound on the output size that hits an internal limitation in
 * talloc.
 *
 * @param mem_ctx      TALLOC_CTX parent for the compressed buffer.
 * @param input_bytes  memory to be compressed.
 * @param input_size   length of the input buffer.
 * @param output       destination pointer for the compressed data.
 *
 * @return the number of bytes written or -1 on error.
 */

ssize_t lzxpress_huffman_compress_talloc(TALLOC_CTX *mem_ctx,
					 const uint8_t *input_bytes,
					 size_t input_size,
					 uint8_t **output)
{
	struct lzxhuff_compressor_mem *cmp = NULL;
	size_t alloc_size = lzxpress_huffman_max_compressed_size(input_size);

	ssize_t output_size;

	*output = talloc_array(mem_ctx, uint8_t, alloc_size);
	if (*output == NULL) {
		return LZXPRESS_ERROR;
	}

	cmp = talloc(mem_ctx, struct lzxhuff_compressor_mem);
	if (cmp == NULL) {
		TALLOC_FREE(*output);
		return LZXPRESS_ERROR;
	}

	output_size = lzxpress_huffman_compress(cmp,
						input_bytes,
						input_size,
						*output,
						alloc_size);

	talloc_free(cmp);

	if (output_size < 0) {
		TALLOC_FREE(*output);
		return LZXPRESS_ERROR;
	}

	*output = talloc_realloc(mem_ctx, *output, uint8_t, output_size);
	if (*output == NULL) {
		return LZXPRESS_ERROR;
	}

	return output_size;
}

/*
 * lzxpress_huffman_compress()
 *
 * This is the inconvenience function, slightly faster and fiddlier than
 * lzxpress_huffman_compress_talloc().
 *
 * To use this, you need to have allocated (but not initialised) a `struct
 * lzxhuff_compressor_mem`, and an output buffer. If the buffer is not big
 * enough (per `output_size`), you'll get a negative return value, otherwise
 * the number of bytes actually consumed, which will always be at least 260.
 *
 * The `struct lzxhuff_compressor_mem` is reusable -- it is basically a
 * collection of uninitialised memory buffers. The total size is less than
 * 150k, so stack allocation is plausible.
 *
 * input_size and available_size are limited to the minimum of UINT32_MAX and
 * SSIZE_MAX. On 64 bit machines that will be UINT32_MAX, or 4GB.
 *
 * @param cmp_mem         a struct lzxhuff_compressor_mem.
 * @param input_bytes     memory to be compressed.
 * @param input_size      length of the input buffer.
 * @param output          destination for the compressed data.
 * @param available_size  allocated output bytes.
 *
 * @return the number of bytes written or -1 on error.
 */
ssize_t lzxpress_huffman_compress(struct lzxhuff_compressor_mem *cmp_mem,
				  const uint8_t *input_bytes,
				  size_t input_size,
				  uint8_t *output,
				  size_t available_size)
{
	size_t i = 0;
	struct lzxhuff_compressor_context cmp_ctx = {
		.input_bytes = input_bytes,
		.input_size = input_size,
		.input_pos = 0,
		.prev_block_pos = 0,
		.output = output,
		.available_size = available_size,
		.output_pos = 0
	};

	if (input_size == 0) {
		/*
		 * We can't deal with this for a number of reasons (e.g. it
		 * breaks the Huffman tree), and the output will be infinitely
		 * bigger than the input. The caller needs to go and think
		 * about what they're trying to do here.
		 */
		return LZXPRESS_ERROR;
	}

	if (input_size > SSIZE_MAX ||
	    input_size > UINT32_MAX ||
	    available_size > SSIZE_MAX ||
	    available_size > UINT32_MAX ||
	    available_size == 0) {
		/*
		 * We use negative ssize_t to return errors, which is limiting
		 * on 32 bit machines; otherwise we adhere to Microsoft's 4GB
		 * limit.
		 *
		 * lzxpress_huffman_compress_talloc() will not get this far,
		 * having already have failed on talloc's 256 MB limit.
		 */
		return LZXPRESS_ERROR;
	}

	if (cmp_mem == NULL ||
	    output == NULL ||
	    input_bytes == NULL) {
		return LZXPRESS_ERROR;
	}

	while (cmp_ctx.input_pos < cmp_ctx.input_size) {
		ssize_t ret;
		ret = lzx_huffman_compress_block(&cmp_ctx,
						 cmp_mem,
						 i);
		if (ret < 0) {
			return ret;
		}
		i++;
	}

	return cmp_ctx.output_pos;
}

static void debug_tree_codes(struct bitstream *input)
{
	/*
	 */
	size_t head = 0;
	size_t tail = 2;
	size_t ffff_count = 0;
	struct q {
		uint16_t tree_code;
		uint16_t code_code;
	};
	struct q queue[65536];
	char bits[17];
	uint16_t *t = input->table;
	queue[0].tree_code = 1;
	queue[0].code_code = 2;
	queue[1].tree_code = 2;
	queue[1].code_code = 3;
	while (head < tail) {
		struct q q = queue[head];
		uint16_t x = t[q.tree_code];
		if (x != 0xffff) {
			int k;
			uint16_t j = q.code_code;
			size_t offset = bitlen_nonzero_16(j) - 1;
			if (unlikely(j == 0)) {
				DBG("BROKEN code is 0!\n");
				return;
			}

			for (k = 0; k <= offset; k++) {
				bool b = (j >> (offset - k)) & 1;
				bits[k] = b ? '1' : '0';
			}
			bits[k] = 0;
			DBG("%03x   %s\n", x & 511, bits);
			head++;
			continue;
		}
		ffff_count++;
		queue[tail].tree_code = q.tree_code * 2 + 1;
		queue[tail].code_code = q.code_code * 2;
		tail++;
		queue[tail].tree_code = q.tree_code * 2 + 1 + 1;
		queue[tail].code_code = q.code_code * 2 + 1;
		tail++;
		head++;
	}
	DBG("0xffff count: %zu\n", ffff_count);
}

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
	uint16_t len = 0, prev_len;
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
	if (CHECK_DEBUGLVL(10)) {
		debug_tree_codes(input);
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
	if (CHECK_DEBUGLVL(10) || DEBUG_HUFFMAN_TREE) {
		debug_huffman_tree_from_table(input->table);
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
	 * 256) in this loop, because the precondition for stopping for the
	 * EOF marker is that the output buffer is full (otherwise, you
	 * wouldn't know which 256 is EOF, rather than an actual symbol), and
	 * we *always* want to stop when the buffer is full. So we work out if
	 * there is an EOF in another loop after we stop writing.
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
			size_t i;
			size_t end = output_pos + length;
			uint8_t *here = output + output_pos;
			uint8_t *there = here - distance;
			if (end > output_size ||
			    previous_size + output_pos < distance ||
			    unlikely(end < output_pos || there > here)) {
				return LZXPRESS_ERROR;
			}
			for (i = 0; i < length; i++) {
				here[i] = there[i];
			}
			output_pos += length;
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
