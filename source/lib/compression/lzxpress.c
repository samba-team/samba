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

#include "includes.h"
#include "replace.h"
#include "lzxpress.h"


#define __BUF_POS_CONST(buf,ofs)(((const uint8_t *)buf)+(ofs))
#define __PULL_BYTE(buf,ofs) \
	((uint8_t)((*__BUF_POS_CONST(buf,ofs)) & 0xFF))

#ifndef PULL_LE_UINT16
#define PULL_LE_UINT16(buf,ofs) ((uint16_t)( \
	((uint16_t)(((uint16_t)(__PULL_BYTE(buf,(ofs)+0))) << 0)) | \
	((uint16_t)(((uint16_t)(__PULL_BYTE(buf,(ofs)+1))) << 8)) \
))
#endif

#ifndef PULL_LE_UINT32
#define PULL_LE_UINT32(buf,ofs) ((uint32_t)( \
	((uint32_t)(((uint32_t)(__PULL_BYTE(buf,(ofs)+0))) <<  0)) | \
	((uint32_t)(((uint32_t)(__PULL_BYTE(buf,(ofs)+1))) <<  8)) | \
	((uint32_t)(((uint32_t)(__PULL_BYTE(buf,(ofs)+2))) << 16)) | \
	((uint32_t)(((uint32_t)(__PULL_BYTE(buf,(ofs)+3))) << 24)) \
))
#endif

static uint32_t xpress_decompress(uint8_t *input,
				uint32_t input_size,
				uint8_t *output,
				uint32_t output_size)
{
	uint32_t output_index, input_index;
	uint32_t indicator, indicator_bit;
	uint32_t length;
	uint32_t offset;
	uint32_t nibble_index;

	output_index = 0;
	input_index = 0;
	indicator = 0;
	indicator_bit = 0;
	length = 0;
	offset = 0;
	nibble_index = 0;

	do {
		if (indicator_bit == 0) {
			indicator = PULL_LE_UINT32(input, input_index);
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
			output[output_index] = input[input_index];
			input_index += sizeof(uint8_t);
			output_index += sizeof(uint8_t);
		} else {
			length = PULL_LE_UINT16(input, input_index);
			input_index += sizeof(uint16_t);
			offset = length / 8;
			length = length % 8;

			if (length == 7) {
				if (nibble_index == 0) {
					nibble_index = input_index;
					length = input[input_index] % 16;
					input_index += sizeof(uint8_t);
				} else {
					length = input[nibble_index] / 16;
					nibble_index = 0;
				}

				if (length == 15) {
					length = input[input_index];
					input_index += sizeof(uint8_t);
						if (length == 255) {
							length = PULL_LE_UINT16(input, input_index);
							input_index += sizeof(uint16_t);
							length -= (15 + 7);
						}
					length += 15;
				}
				length += 7;
			}

			length += 3;

			do {
				if (output_index >= output_size) break;
				output[output_index] = output[output_index - offset - 1];
				output_index += sizeof(uint8_t);
				length -= sizeof(uint8_t);
			} while (length != 0);
		}

	} while ((output_index < output_size) && (input_index < input_size));

	return output_index;
}

uint32_t lzxpress_decompress(DATA_BLOB *inbuf,
				DATA_BLOB *outbuf)
{
	return xpress_decompress(inbuf->data, inbuf->length, outbuf->data, outbuf->length);
}
