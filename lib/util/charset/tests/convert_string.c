/* 
   Unix SMB/CIFS implementation.
   test suite for the charcnv functions

   Copyright (C) Andrew Bartlett 2011
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/torture.h"
#include "lib/util/charset/charset.h"
#include "param/param.h"
#include "lib/util/base64.h"

struct torture_suite *torture_local_convert_string_handle(TALLOC_CTX *mem_ctx);
struct torture_suite *torture_local_string_case_handle(TALLOC_CTX *mem_ctx);
struct torture_suite *torture_local_convert_string(TALLOC_CTX *mem_ctx);
struct torture_suite *torture_local_string_case(TALLOC_CTX *mem_ctx);

/* The text below is in ancient and a latin charset transliteration of
 * greek, and an english translation.  It from Apology by Plato and sourced from
 * http://en.wikipedia.org/w/index.php?title=Ancient_Greek&oldid=421361065#Example_text
 */

const char *plato_english_ascii = 
	"What you, men of Athens, have learned from my accusers, I do not"
	" know: but I, for my part, nearly forgot who I was thanks to them since"
	" they spoke so persuasively. And yet, of the truth, they have spoken,"
	" one might say, nothing at all.";

const char *plato_english_utf16le_base64 =
	"VwBoAGEAdAAgAHkAbwB1ACwAIABtAGUAbgAgAG8AZgAgAEEAdABoAGUAbgBzACwAIABoAGEAdgBl"
	"ACAAbABlAGEAcgBuAGUAZAAgAGYAcgBvAG0AIABtAHkAIABhAGMAYwB1AHMAZQByAHMALAAgAEkA"
	"IABkAG8AIABuAG8AdAAgAGsAbgBvAHcAOgAgAGIAdQB0ACAASQAsACAAZgBvAHIAIABtAHkAIABw"
	"AGEAcgB0ACwAIABuAGUAYQByAGwAeQAgAGYAbwByAGcAbwB0ACAAdwBoAG8AIABJACAAdwBhAHMA"
	"IAB0AGgAYQBuAGsAcwAgAHQAbwAgAHQAaABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQB5ACAAcwBw"
	"AG8AawBlACAAcwBvACAAcABlAHIAcwB1AGEAcwBpAHYAZQBsAHkALgAgAEEAbgBkACAAeQBlAHQA"
	"LAAgAG8AZgAgAHQAaABlACAAdAByAHUAdABoACwAIAB0AGgAZQB5ACAAaABhAHYAZQAgAHMAcABv"
	"AGsAZQBuACwAIABvAG4AZQAgAG0AaQBnAGgAdAAgAHMAYQB5ACwAIABuAG8AdABoAGkAbgBnACAA"
	"YQB0ACAAYQBsAGwALgA=";

static const char *plato_utf8_base64 = 
	"4b2Nz4TOuSDOvOG9ss69IOG9kc68zrXhv5bPgiwg4b2mIOG8hM69zrTPgc61z4IgzobOuM63zr3O"
	"seG/ls6/zrksIM+AzrXPgM+Mzr3OuM6xz4TOtSDhvZHPgOG9uCDPhOG/ts69IOG8kM684b+2zr0g"
	"zrrOsc+EzrfOs8+Mz4HPic69LCDOv+G9kM66IM6/4by2zrTOsTog4byQzrPhvbwgzrQnIM6/4b2W"
	"zr0gzrrOseG9tiDOseG9kM+E4b24z4Ig4b2Rz4AnIM6x4b2Qz4Thv7bOvSDhvYDOu86vzrPOv8+F"
	"IOG8kM68zrHPhc+Ezr/hv6Yg4byQz4DOtc67zrHOuM+MzrzOt869LCDOv+G9lc+Ez4kgz4DOuc64"
	"zrHOveG/ts+CIOG8lM67zrXOs86/zr0uIM6azrHOr8+Ezr/OuSDhvIDOu863zrjOrc+CIM6zzrUg"
	"4b2hz4Ig4byUz4DOv8+CIM614bywz4DOteG/ls69IM6/4b2QzrThvbLOvSDOteG8sM+Bzq7Ous6x"
	"z4POuc69Lg==";

static const char *plato_utf16le_base64 = 
	"TR/EA7kDIAC8A3IfvQMgAFEfvAO1A9YfwgMsACAAZh8gAAQfvQO0A8EDtQPCAyAAhgO4A7cDvQOx"
	"A9YfvwO5AywAIADAA7UDwAPMA70DuAOxA8QDtQMgAFEfwAN4HyAAxAP2H70DIAAQH7wD9h+9AyAA"
	"ugOxA8QDtwOzA8wDwQPJA70DLAAgAL8DUB+6AyAAvwM2H7QDsQM6ACAAEB+zA3wfIAC0AycAIAC/"
	"A1YfvQMgALoDsQN2HyAAsQNQH8QDeB/CAyAAUR/AAycAIACxA1AfxAP2H70DIABAH7sDrwOzA78D"
	"xQMgABAfvAOxA8UDxAO/A+YfIAAQH8ADtQO7A7EDuAPMA7wDtwO9AywAIAC/A1UfxAPJAyAAwAO5"
	"A7gDsQO9A/YfwgMgABQfuwO1A7MDvwO9Ay4AIACaA7EDrwPEA78DuQMgAAAfuwO3A7gDrQPCAyAA"
	"swO1AyAAYR/CAyAAFB/AA78DwgMgALUDMB/AA7UD1h+9AyAAvwNQH7QDch+9AyAAtQMwH8EDrgO6"
	"A7EDwwO5A70DLgA=";

static const char *plato_latin_utf8_base64 = 
	"SMOzdGkgbcOobiBodW1lw65zLCDDtCDDoW5kcmVzIEF0aMSTbmHDrm9pLCBwZXDDs250aGF0ZSBo"
	"dXDDsiB0w7RuIGVtw7RuIGthdMSTZ8OzcsWNbiwgb3VrIG/DrmRhOiBlZ+G5kSBkJyBvw7tuIGth"
	"w6wgYXV0w7JzIGh1cCcgYXV0xY1uIG9sw61nb3UgZW1hdXRvw7sgZXBlbGF0aMOzbcSTbiwgaG/D"
	"unTFjSBwaXRoYW7DtHMgw6lsZWdvbi4gS2HDrXRvaSBhbMSTdGjDqXMgZ2UgaMWNcyDDqXBvcyBl"
	"aXBlw65uIG91ZMOobiBlaXLhuJdrYXNpbi4=";

static const char *plato_latin_utf16le_base64 = 
	"SADzAHQAaQAgAG0A6ABuACAAaAB1AG0AZQDuAHMALAAgAPQAIADhAG4AZAByAGUAcwAgAEEAdABo"
	"ABMBbgBhAO4AbwBpACwAIABwAGUAcADzAG4AdABoAGEAdABlACAAaAB1AHAA8gAgAHQA9ABuACAA"
	"ZQBtAPQAbgAgAGsAYQB0ABMBZwDzAHIATQFuACwAIABvAHUAawAgAG8A7gBkAGEAOgAgAGUAZwBR"
	"HiAAZAAnACAAbwD7AG4AIABrAGEA7AAgAGEAdQB0APIAcwAgAGgAdQBwACcAIABhAHUAdABNAW4A"
	"IABvAGwA7QBnAG8AdQAgAGUAbQBhAHUAdABvAPsAIABlAHAAZQBsAGEAdABoAPMAbQATAW4ALAAg"
	"AGgAbwD6AHQATQEgAHAAaQB0AGgAYQBuAPQAcwAgAOkAbABlAGcAbwBuAC4AIABLAGEA7QB0AG8A"
	"aQAgAGEAbAATAXQAaADpAHMAIABnAGUAIABoAE0BcwAgAOkAcABvAHMAIABlAGkAcABlAO4AbgAg"
	"AG8AdQBkAOgAbgAgAGUAaQByABceawBhAHMAaQBuAC4A";

static const char *gd_utf8_base64 = "R8O8bnRoZXIgRGVzY2huZXI=";
static const char *gd_utf8_upper_base64 = "R8OcTlRIRVIgREVTQ0hORVI=";
static const char *gd_utf8_lower_base64 = "Z8O8bnRoZXIgZGVzY2huZXI=";
static const char *gd_cp850_base64 = "R4FudGhlciBEZXNjaG5lcg==";
static const char *gd_cp850_upper_base64 = "R5pOVEhFUiBERVNDSE5FUg==";
static const char *gd_cp850_lower_base64 = "Z4FudGhlciBkZXNjaG5lcg==";
static const char *gd_iso8859_1_base64 = "R/xudGhlciBEZXNjaG5lcg==";
static const char *gd_utf16le_base64 = "RwD8AG4AdABoAGUAcgAgAEQAZQBzAGMAaABuAGUAcgA=";
/* täst */
static const char *utf8_nfc_base64 = "dMOkc3QA";
/* täst, where ä = a + combining diaeresis */
static const char *utf8_nfd_base64 = "dGHMiHN0AA==";

/*
 * These cp850 bytes correspond to high Unicode codes, stretching out to
 * 3-byte sequences in utf-8.
 */
static const char *cp850_high_points = "\xb9\xba\xbb\xbc\xcd\xce";
static const char *utf8_high_points = "╣║╗╝═╬";

static bool test_cp850_high_points(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle = NULL;
	DATA_BLOB cp850 = data_blob_string_const(cp850_high_points);
	DATA_BLOB utf8;
	DATA_BLOB cp850_return;

	iconv_handle = get_iconv_testing_handle(tctx, "CP850", "UTF8",
						lpcfg_parm_bool(tctx->lp_ctx,
								NULL,
								"iconv",
								"use_builtin_handlers",
								true));

	torture_assert(tctx, iconv_handle, "creating iconv handle");

	torture_assert(tctx,
		       convert_string_talloc_handle(tctx, iconv_handle,
						    CH_DOS, CH_UTF8,
						    cp850.data, cp850.length,
						    (void *)&utf8.data, &utf8.length),
		       "conversion from CP850 to UTF-8");

	torture_assert(tctx, utf8.length == cp850.length * 3,
		       "CP850 high bytes expand to the right size");

	torture_assert(tctx,
		       memcmp(utf8.data, utf8_high_points, utf8.length) == 0,
		       "cp850 converted to utf8 matches expected value");

	torture_assert(tctx,
		       convert_string_talloc_handle(tctx, iconv_handle,
						    CH_UTF8, CH_DOS,
						    utf8.data, utf8.length,
						    (void *)&cp850_return.data,
						    &cp850_return.length),
		       "conversion from UTF-8 back to CP850");

	torture_assert(tctx, data_blob_cmp(&cp850_return, &cp850) == 0,
		       "UTF-8 returned to CP850 matches the original");
	return true;
}


static bool test_gd_iso8859_cp850_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB gd_utf8 = base64_decode_data_blob(gd_utf8_base64);
	DATA_BLOB gd_cp850 = base64_decode_data_blob(gd_cp850_base64);
	DATA_BLOB gd_iso8859_1 = base64_decode_data_blob(gd_iso8859_1_base64);
	DATA_BLOB gd_utf16le = base64_decode_data_blob(gd_utf16le_base64);
	DATA_BLOB gd_output;
	DATA_BLOB gd_output2;
	
	talloc_steal(tctx, gd_utf8.data);
	talloc_steal(tctx, gd_cp850.data);
	talloc_steal(tctx, gd_iso8859_1.data);
	talloc_steal(tctx, gd_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ISO-8859-1", "CP850",
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting iconv handle");
		
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DOS, 
						    gd_utf8.data, gd_utf8.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF8 to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF8 to (dos charset) ISO-8859-1 incorrect");
	
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length),
		       "conversion from UTF8 to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF8 to (dos charset) ISO-8859-1 incorrect");

	/* Short output handling confirmation */
	gd_output.length = 1;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ISO-8859-1 should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to (dos charset) ISO-8859-1 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	torture_assert_data_blob_equal(tctx, gd_output, data_blob_string_const("G"), "conversion from UTF8 to (dos charset) ISO-8859-1 incorrect");

	/* Short output handling confirmation */
	gd_output.length = 2;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ISO-8859-1 should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to (dos charset) ISO-8859-1 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 2, "Should only get 2 char of output");

	/* Short input handling confirmation */
	gd_output.length = gd_iso8859_1.length;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, 2,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ISO-8859-1 should fail due to too short");
	torture_assert_errno_equal(tctx, EILSEQ, "conversion from short UTF8 to (dos charset) ISO-8859-1 should fail EINVAL");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");

	/* Short output handling confirmation */
	gd_output.length = 1;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le.data, gd_utf16le.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF16 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16 to (utf8 charset) ISO-8859-1 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	torture_assert_data_blob_equal(tctx, gd_output, data_blob_string_const("G"), "conversion from UTF16 to UTF8 incorrect");

	/* Short output handling confirmation */
	gd_output.length = 3;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le.data, gd_utf16le.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF16 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16 to (utf8 charset) ISO-8859-1 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 3, "Should get 3 bytes output for UTF8");

	/* Short input handling confirmation */
	gd_output.length = gd_utf8.length;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le.data, 3,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF16 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, EINVAL, "conversion from short UTF16 to UTF8 should fail EINVAL");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UNIX, 
						    gd_utf8.data, gd_utf8.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF8 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850, "conversion from UTF8 to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UTF8, 
						    gd_utf8.data, gd_utf8.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF8 to UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF8 to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    gd_utf16le.data, gd_utf16le.length, 
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from UTF16LE to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF16LE to (dos charset) ISO-8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    gd_output.data, gd_output.length, 
						    (void *)&gd_output2.data, &gd_output2.length),
		       "round trip conversion from (dos charset) ISO-8859-1 back to UTF16LE");
	torture_assert_data_blob_equal(tctx, gd_output2, gd_utf16le,  "round trip conversion from (dos charset) ISO-8859-1 back to UTF16LE");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UNIX, 
						    gd_utf16le.data, gd_utf16le.length, 
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from UTF16LE to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UTF8, 
						    gd_utf16le.data, gd_utf16le.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF16LE to UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF16LE to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_DOS, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from (dos charset) ISO-8859-1 to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF16LE to (dos charset) ISO-8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UNIX, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from (dos charset) ISO-8859-1 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF8, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from (dos charset) ISO-8859-1 to UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF16LE to UTF8 incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from (dos charset) ISO-8859-1 to UTF16LE");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le, "conversion from (dos charset) ISO-8859-1 to UTF16LE");
	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)gd_iso8859_1.data,
						     CH_DOS, CH_UTF16LE),
				 gd_output.length / 2,
				 "checking strlen_m_ext of round trip conversion of UTF16 latin charset greek to UTF8 and back again");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
						    CH_DOS, CH_UTF8,
						    gd_iso8859_1.data, gd_iso8859_1.length,
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from (dos charset) ISO-8859-1 to UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from (dos charset) ISO-8859-1 to UTF8");
	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)gd_iso8859_1.data,
						     CH_DOS, CH_UTF8),
				 gd_output.length,
				 "checking strlen_m_ext of conversion from (dos charset) ISO-8859-1 to UTF8");
	return true;
}

static bool test_gd_minus_1_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB gd_utf8 = base64_decode_data_blob(gd_utf8_base64);
	DATA_BLOB gd_cp850 = base64_decode_data_blob(gd_cp850_base64);
	DATA_BLOB gd_utf16le = base64_decode_data_blob(gd_utf16le_base64);
	DATA_BLOB gd_output;
	DATA_BLOB gd_utf8_terminated;
	DATA_BLOB gd_cp850_terminated;
	DATA_BLOB gd_utf16le_terminated;
	
	talloc_steal(tctx, gd_utf8.data);
	talloc_steal(tctx, gd_cp850.data);
	talloc_steal(tctx, gd_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "CP850", "CP850", 
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting iconv handle");

	gd_utf8_terminated = data_blob_talloc(tctx, NULL, gd_utf8.length + 1);
	memcpy(gd_utf8_terminated.data, gd_utf8.data, gd_utf8.length);
	gd_utf8_terminated.data[gd_utf8.length] = '\0';

	gd_cp850_terminated = data_blob_talloc(tctx, NULL, gd_cp850.length + 1);
	memcpy(gd_cp850_terminated.data, gd_cp850.data, gd_cp850.length);
	gd_cp850_terminated.data[gd_cp850.length] = '\0';

	gd_utf16le_terminated = data_blob_talloc(tctx, NULL, gd_utf16le.length + 2);
	memcpy(gd_utf16le_terminated.data, gd_utf16le.data, gd_utf16le.length);
	gd_utf16le_terminated.data[gd_utf16le.length] = '\0';
	gd_utf16le_terminated.data[gd_utf16le.length + 1] = '\0';

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  gd_utf8_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  gd_utf8_terminated.data, -1,
							  (void *)gd_output.data, gd_utf16le.length, &gd_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le, "conversion from UTF8 to UTF16LE null terminated");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  gd_utf8_terminated.data, -1,
							  (void *)gd_output.data, gd_utf16le.length - 1, &gd_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  gd_utf8_terminated.data, -1,
							  (void *)gd_output.data, gd_utf16le.length - 2, &gd_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length + 10);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_utf8.length, &gd_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF16LE to UTF8 null terminated");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_utf8.length - 1, &gd_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_utf8.length - 2, &gd_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");

	gd_output = data_blob_talloc(tctx, NULL, gd_cp850.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_DOS,
							 gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF16LE to CP850 (dos) null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850_terminated, "conversion from UTF16LE to CP850 (dos) null terminated");

	/* Now null terminate the string early, the confirm we don't skip the NULL and convert any further */
	gd_utf8_terminated.data[3] = '\0';
	gd_utf8_terminated.length = 4; /* used for the comparison only */

	gd_cp850_terminated.data[2] = '\0';
	gd_cp850_terminated.length = 3; /* used for the comparison only */

	gd_utf16le_terminated.data[4] = '\0';
	gd_utf16le_terminated.data[5] = '\0';
	gd_utf16le_terminated.length = 6; /* used for the comparison only */

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  gd_utf8_terminated.data, -1,
							  (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated early");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF16LE, CH_UTF8,
							  gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated early");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_DOS, CH_UTF16LE,
							  gd_cp850_terminated.data, -1,
							  (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from CP850 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated early");

	gd_output = data_blob_talloc(tctx, NULL, gd_cp850.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF16LE, CH_DOS,
							  gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850_terminated, "conversion from UTF16LE to UTF8 null terminated early");
	
	/* Now null terminate the string particularly early, the confirm we don't skip the NULL and convert any further */
	gd_utf8_terminated.data[1] = '\0';
	gd_utf8_terminated.length = 2; /* used for the comparison only */
	
	gd_utf16le_terminated.data[2] = '\0';
	gd_utf16le_terminated.data[3] = '\0';
	gd_utf16le_terminated.length = 4; /* used for the comparison only */

	gd_output = data_blob_talloc(tctx, NULL, gd_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle, CH_UTF8, CH_UTF16LE,
							  gd_utf8_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated very early");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF16LE, CH_UTF8,
							  gd_utf16le_terminated.data, -1,
							 (void *)gd_output.data, gd_output.length, &gd_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated very early");

	return true;
}

static bool test_gd_ascii_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB gd_utf8 = base64_decode_data_blob(gd_utf8_base64);
	DATA_BLOB gd_cp850 = base64_decode_data_blob(gd_cp850_base64);
	DATA_BLOB gd_iso8859_1 = base64_decode_data_blob(gd_iso8859_1_base64);
	DATA_BLOB gd_utf16le = base64_decode_data_blob(gd_utf16le_base64);
	DATA_BLOB gd_output;

	talloc_steal(tctx, gd_utf8.data);
	talloc_steal(tctx, gd_cp850.data);
	talloc_steal(tctx, gd_iso8859_1.data);
	talloc_steal(tctx, gd_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ASCII", "UTF8", 
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting iconv handle");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
						    CH_UTF8, CH_DOS,
						    gd_utf8.data, gd_utf8.length,
						    (void *)&gd_output.data, &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ASCII should fail");

	gd_output = data_blob_talloc(tctx, NULL, gd_utf8.length);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ASCII should fail");
	torture_assert_errno_equal(tctx, EILSEQ, "conversion from UTF8 to (dos charset) ISO-8859-1 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	torture_assert_data_blob_equal(tctx, gd_output, data_blob_string_const("G"), "partial conversion from UTF8 to (dos charset) ASCII incorrect");

	/* Short output handling confirmation */
	gd_output.length = 1;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ASCII should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to (dos charset) ASCII too short");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	torture_assert_data_blob_equal(tctx, gd_output, data_blob_string_const("G"), "conversion from UTF8 to (dos charset) ASCII incorrect");

	/* Short output handling confirmation */
	gd_output.length = 2;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ASCII should fail due to too illigal seqence");
	torture_assert_errno_equal(tctx, EILSEQ, "conversion from UTF8 to (dos charset) ISO-8859-1 should fail EILSEQ");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 2 char of output");

	/* Short input handling confirmation */
	gd_output.length = gd_utf8.length;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_DOS,
							 gd_utf8.data, 2,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to (dos charset) ASCII should fail due to too short");
	torture_assert_errno_equal(tctx, EILSEQ, "conversion from short UTF8 to (dos charset) ASCII should fail EILSEQ");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	return true;
}

static bool test_plato_english_iso8859_cp850_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_english_utf8 = data_blob_string_const(plato_english_ascii);
	DATA_BLOB plato_english_cp850 = plato_english_utf8;
	DATA_BLOB plato_english_iso8859_1 = plato_english_utf8;
	DATA_BLOB plato_english_utf16le = base64_decode_data_blob(plato_english_utf16le_base64);
	DATA_BLOB plato_english_output;
	DATA_BLOB plato_english_output2;
	
	talloc_steal(tctx, plato_english_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ISO-8859-1", "CP850", 
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting iconv handle");
		
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DOS, 
						    plato_english_utf8.data, plato_english_utf8.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF8 to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_iso8859_1, "conversion from UTF8 to (dos charset) ISO-8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UNIX, 
						    plato_english_utf8.data, plato_english_utf8.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF8 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_cp850, "conversion from UTF8 to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UTF8, 
						    plato_english_utf8.data, plato_english_utf8.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF8 to UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF8 to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    plato_english_utf16le.data, plato_english_utf16le.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from UTF16LE to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_iso8859_1, "conversion from UTF16LE to (dos charset) ISO-8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    plato_english_output.data, plato_english_output.length, 
						    (void *)&plato_english_output2.data, &plato_english_output2.length),
		       "round trip conversion from (dos charset) ISO-8859-1 back to UTF16LE");
	torture_assert_data_blob_equal(tctx, plato_english_output2, plato_english_utf16le,  "round trip conversion from (dos charset) ISO-8859-1 back to UTF16LE");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UTF8,
						    plato_english_utf16le.data, plato_english_utf16le.length,
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from UTF16LE to UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to UTF8 incorrect");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_english_utf16le.data, plato_english_utf16le.length,
							 (void *)plato_english_output.data, plato_english_output.length,
							 &plato_english_output.length),
		       "conversion from UTF16LE to UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to UTF8 incorrect");

	plato_english_output.length = 5;
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_english_utf16le.data, plato_english_utf16le.length,
							 (void *)plato_english_output.data, plato_english_output.length,
							 &plato_english_output.length) == false,
		       "conversion from UTF16LE to UTF8 should fail due to short output");
	torture_assert_data_blob_equal(tctx, plato_english_output, data_blob_string_const("What "), "conversion from UTF16LE to UTF8 incorrect");
	torture_assert_int_equal(tctx, plato_english_output.length, 5, "short conversion failed");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
						    CH_UTF16LE, CH_UNIX, 
						    plato_english_utf16le.data, plato_english_utf16le.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from UTF16LE to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UTF8, 
						    plato_english_utf16le.data, plato_english_utf16le.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF16LE to UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_DOS, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from (dos charset) ISO-8859-1 to (dos charset) ISO-8859-1");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_iso8859_1, "conversion from UTF16LE to (dos charset) ISO-8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UNIX, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from (dos charset) ISO-8859-1 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF8, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from (dos charset) ISO-8859-1 to UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to UTF8 incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from (dos charset) ISO-8859-1 to UTF16LE");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf16le, "conversion from (dos charset) ISO-8859-1 to UTF16LE");
	return true;
}

static bool test_plato_english_minus_1_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_english_utf8 = data_blob_string_const(plato_english_ascii);
	DATA_BLOB plato_english_utf16le = base64_decode_data_blob(plato_english_utf16le_base64);
	DATA_BLOB plato_english_output;
	DATA_BLOB plato_english_utf8_terminated;
	DATA_BLOB plato_english_utf16le_terminated;
	
	talloc_steal(tctx, plato_english_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ISO-8859-1", "CP850", 
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting iconv handle");

	plato_english_utf8_terminated = data_blob_talloc(tctx, NULL, plato_english_utf8.length + 1);
	memcpy(plato_english_utf8_terminated.data, plato_english_utf8.data, plato_english_utf8.length);
	plato_english_utf8_terminated.data[plato_english_utf8.length] = '\0';

	plato_english_utf16le_terminated = data_blob_talloc(tctx, NULL, plato_english_utf16le.length + 2);
	memcpy(plato_english_utf16le_terminated.data, plato_english_utf16le.data, plato_english_utf16le.length);
	plato_english_utf16le_terminated.data[plato_english_utf16le.length] = '\0';
	plato_english_utf16le_terminated.data[plato_english_utf16le.length + 1] = '\0';
		
	plato_english_output = data_blob_talloc(tctx, NULL, plato_english_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_english_utf8_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_output.length, &plato_english_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_english_utf8_terminated.data, -1,
							  (void *)plato_english_output.data, plato_english_utf16le.length, &plato_english_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf16le, "conversion from UTF8 to UTF16LE null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_english_utf8_terminated.data, -1,
							  (void *)plato_english_output.data, plato_english_utf16le.length - 1, &plato_english_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_english_utf8_terminated.data, -1,
							  (void *)plato_english_output.data, plato_english_utf16le.length - 2, &plato_english_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");

	plato_english_output = data_blob_talloc(tctx, NULL, plato_english_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_english_utf16le_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_output.length, &plato_english_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_english_utf16le_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_utf8.length, &plato_english_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to UTF8 null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_english_utf16le_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_utf8.length - 1, &plato_english_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_english_utf16le_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_utf8.length - 2, &plato_english_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");

	/* Now null terminate the string early, the confirm we don't skip the NULL and convert any further */
	plato_english_utf8_terminated.data[3] = '\0';
	plato_english_utf8_terminated.length = 4; /* used for the comparison only */

	plato_english_utf16le_terminated.data[6] = '\0';
	plato_english_utf16le_terminated.data[7] = '\0';
	plato_english_utf16le_terminated.length = 8; /* used for the comparison only */

	plato_english_output = data_blob_talloc(tctx, NULL, plato_english_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_english_utf8_terminated.data, -1,
							  (void *)plato_english_output.data, plato_english_output.length, &plato_english_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated early");

	plato_english_output = data_blob_talloc(tctx, NULL, plato_english_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF16LE, CH_UTF8,
							  plato_english_utf16le_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_output.length, &plato_english_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated early");

	
	/* Now null terminate the string particularly early, the confirm we don't skip the NULL and convert any further */
	plato_english_utf8_terminated.data[1] = '\0';
	plato_english_utf8_terminated.length = 2; /* used for the comparison only */
	
	plato_english_utf16le_terminated.data[2] = '\0';
	plato_english_utf16le_terminated.data[3] = '\0';
	plato_english_utf16le_terminated.length = 4; /* used for the comparison only */

	plato_english_output = data_blob_talloc(tctx, NULL, plato_english_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle, CH_UTF8, CH_UTF16LE,
							  plato_english_utf8_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_output.length, &plato_english_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated very early");

	plato_english_output = data_blob_talloc(tctx, NULL, plato_english_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF16LE, CH_UTF8,
							  plato_english_utf16le_terminated.data, -1,
							 (void *)plato_english_output.data, plato_english_output.length, &plato_english_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated very early");

	return true;
}

static bool test_plato_minus_1_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_utf8 = base64_decode_data_blob(plato_utf8_base64);
	DATA_BLOB plato_utf16le = base64_decode_data_blob(plato_utf16le_base64);
	DATA_BLOB plato_output;
	DATA_BLOB plato_utf8_terminated;
	DATA_BLOB plato_utf16le_terminated;
	
	talloc_steal(tctx, plato_utf8.data);
	talloc_steal(tctx, plato_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ISO-8859-1", "CP850",
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting iconv handle");

	plato_utf8_terminated = data_blob_talloc(tctx, NULL, plato_utf8.length + 1);
	memcpy(plato_utf8_terminated.data, plato_utf8.data, plato_utf8.length);
	plato_utf8_terminated.data[plato_utf8.length] = '\0';

	plato_utf16le_terminated = data_blob_talloc(tctx, NULL, plato_utf16le.length + 2);
	memcpy(plato_utf16le_terminated.data, plato_utf16le.data, plato_utf16le.length);
	plato_utf16le_terminated.data[plato_utf16le.length] = '\0';
	plato_utf16le_terminated.data[plato_utf16le.length + 1] = '\0';

	plato_output = data_blob_talloc(tctx, NULL, plato_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_utf8_terminated.data, -1,
							 (void *)plato_output.data, plato_output.length, &plato_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_utf8_terminated.data, -1,
							  (void *)plato_output.data, plato_utf16le.length, &plato_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le, "conversion from UTF8 to UTF16LE null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_utf8_terminated.data, -1,
							  (void *)plato_output.data, plato_utf16le.length - 1, &plato_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_utf8_terminated.data, -1,
							  (void *)plato_output.data, plato_utf16le.length - 2, &plato_output.length) == false,
		       "conversion from UTF8 to UTF16LE null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to UTF16LE should fail E2BIG");

	plato_output = data_blob_talloc(tctx, NULL, plato_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_utf16le_terminated.data, -1,
							 (void *)plato_output.data, plato_output.length, &plato_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_utf16le_terminated.data, -1,
							 (void *)plato_output.data, plato_utf8.length, &plato_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF16LE to UTF8 null terminated");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_utf16le_terminated.data, -1,
							 (void *)plato_output.data, plato_utf8.length - 1, &plato_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_utf16le_terminated.data, -1,
							 (void *)plato_output.data, plato_utf8.length - 2, &plato_output.length) == false,
		       "conversion from UTF16LE to UTF8 null terminated should fail");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16LE to UTF8 should fail E2BIG");

	/* Now null terminate the string early, the confirm we don't skip the NULL and convert any further */
	plato_utf8_terminated.data[5] = '\0';
	plato_utf8_terminated.length = 6; /* used for the comparison only */

	plato_utf16le_terminated.data[4] = '\0';
	plato_utf16le_terminated.data[5] = '\0';
	plato_utf16le_terminated.length = 6; /* used for the comparison only */

	plato_output = data_blob_talloc(tctx, NULL, plato_utf16le.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF8, CH_UTF16LE,
							  plato_utf8_terminated.data, -1,
							  (void *)plato_output.data, plato_output.length, &plato_output.length),
		       "conversion from UTF8 to UTF16LE null terminated");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le_terminated, "conversion from UTF8 to UTF16LE null terminated early");

	plato_output = data_blob_talloc(tctx, NULL, plato_utf8.length + 10);

	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							  CH_UTF16LE, CH_UTF8,
							  plato_utf16le_terminated.data, -1,
							 (void *)plato_output.data, plato_output.length, &plato_output.length),
		       "conversion from UTF16LE to UTF8 null terminated");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8_terminated, "conversion from UTF16LE to UTF8 null terminated early");
	
	return true;
}

static bool test_plato_cp850_utf8_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_utf8 = base64_decode_data_blob(plato_utf8_base64);
	DATA_BLOB plato_utf16le = base64_decode_data_blob(plato_utf16le_base64);
	DATA_BLOB plato_output;
	DATA_BLOB plato_output2;
	
	talloc_steal(tctx, plato_utf8.data);
	talloc_steal(tctx, plato_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "CP850", "UTF8", 
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "creating iconv handle");
		
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UTF16LE,
						    plato_utf8.data, plato_utf8.length,
						    (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le, "conversion from UTF8 to UTF16LE incorrect");

	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)plato_utf8.data,
						     CH_UTF8, CH_UTF16LE),
				 plato_output.length / 2,
				 "checking strlen_m_ext of conversion of UTF8 to UTF16LE");

	memset(plato_output.data, '\0', plato_output.length);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_UTF16LE,
							 plato_utf8.data, plato_utf8.length,
							 (void *)plato_output.data, plato_output.length,
							 &plato_output.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le, "conversion from UTF8 to UTF16LE incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
						    CH_UTF16LE, CH_UTF8,
						    plato_output.data, plato_output.length,
						    (void *)&plato_output2.data, &plato_output2.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf8, "conversion from UTF8 to UTF16LE incorrect");

	memset(plato_output2.data, '\0', plato_output2.length);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
						   CH_UTF16LE, CH_UTF8,
						   plato_output.data, plato_output.length,
						   (void *)plato_output2.data, plato_output2.length, &plato_output2.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf8, "conversion from UTF8 to UTF16LE incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
							  CH_UTF8, CH_UTF8,
							  plato_utf8.data, plato_utf8.length,
							  (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF8 to UTF8");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8,
				       "conversion of UTF8 to UTF8");
	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)plato_utf8.data,
						     CH_UTF8, CH_UTF8),
				 plato_output.length,
				 "checking strlen_m_ext of conversion of UTF8 to UTF8");
	memset(plato_output.data, '\0', plato_output.length);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_UTF8,
							 plato_utf8.data, plato_utf8.length,
							 (void *)plato_output.data, plato_output.length,
							 &plato_output.length),
		       "conversion of UTF8 to UTF8");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
						    CH_UTF8, CH_DOS, 
						    plato_utf8.data, plato_utf8.length, 
						    (void *)&plato_output.data, &plato_output.length) == false, 
		       "conversion of UTF8 ancient greek to DOS charset CP850 should fail");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UNIX, 
						    plato_utf8.data, plato_utf8.length, 
						    (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF16 ancient greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF8 to (unix charset) UTF8 incorrect");
	
	memset(plato_output.data, '\0', plato_output.length);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF8, CH_UNIX,
							 plato_utf8.data, plato_utf8.length,
							 (void *)plato_output.data, plato_output.length,
							 &plato_output.length),
		       "conversion of UTF16 ancient greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF8 to (unix charset) UTF8 incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UTF8, 
						    plato_utf8.data, plato_utf8.length, 
						    (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF16 ancient greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF8 to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    plato_utf16le.data, plato_utf16le.length, 
						    (void *)&plato_output.data, &plato_output.length) == false, 	
		       "conversion of UTF16 ancient greek to DOS charset CP850 should fail");

	/* Allocate enough space, if it were possible do do the conversion */
	plato_output = data_blob_talloc(tctx, NULL, plato_utf16le.length);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_DOS,
							 plato_utf16le.data, plato_utf16le.length,
							 (void *)plato_output.data, plato_output.length,
							 &plato_output.length) == false,
		       "conversion of UTF16 ancient greek to DOS charset CP850 should fail");
	torture_assert_errno_equal(tctx,  EILSEQ, "conversion of UTF16 ancient greek to DOS charset CP850 should fail");

	/* Allocate only enough space for a partial conversion */
	plato_output = data_blob_talloc(tctx, NULL, 9);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_utf16le.data, plato_utf16le.length,
							 (void *)plato_output.data, plato_output.length,
							 &plato_output.length) == false,
		       "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_errno_equal(tctx,  E2BIG, "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_int_equal(tctx, plato_output.length, 8,
				 "conversion of UTF16 ancient greek to UTF8 should stop on multibyte boundary");

	plato_output = data_blob_talloc(tctx, NULL, 2);
	torture_assert(tctx, convert_string_error_handle(iconv_handle,
							 CH_UTF16LE, CH_UTF8,
							 plato_utf16le.data, plato_utf16le.length,
							 (void *)plato_output.data, plato_output.length,
							 &plato_output.length) == false,
		       "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_errno_equal(tctx,  E2BIG, "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_int_equal(tctx, plato_output.length, 0,
				 "conversion of UTF16 ancient greek to UTF8 should stop on multibyte boundary");


	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UNIX, 
						    plato_utf16le.data, plato_utf16le.length, 
						    (void *)&plato_output.data, &plato_output.length), 	
		       "conversion of UTF16 ancient greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF16LE to (unix charset) UTF8 incorrect");
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
						    CH_UTF16LE, CH_UTF8,
						    plato_utf16le.data, plato_utf16le.length,
						    (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF16 ancient greek to UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF16LE to UTF8 incorrect");
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_UTF16LE, CH_UTF8, 
							  plato_utf16le.data, plato_utf16le.length, 
							  (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF16 ancient greek to UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF16LE to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_UTF8, CH_UTF16LE, 
							  plato_output.data, plato_output.length, 
							  (void *)&plato_output2.data, &plato_output2.length),
		       "round trip conversion of UTF16 ancient greek to UTF8 and back again failed");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf16le,
				       "round trip conversion of UTF16 ancient greek to UTF8 and back again failed");
	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)plato_output.data,
						     CH_UTF8, CH_UTF16LE),
				 plato_output2.length / 2,
				 "checking strlen_m_ext of round trip conversion of UTF16 latin charset greek to UTF8 and back again");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle,
							  CH_UTF8, CH_UTF8,
							  plato_output.data, plato_output.length,
							  (void *)&plato_output2.data, &plato_output2.length),
		       "conversion of UTF8 to UTF8");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf8,
				       "conversion of UTF8 to UTF8");
	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)plato_output.data,
						     CH_UTF8, CH_UTF8),
				 plato_output2.length,
				 "checking strlen_m_ext of conversion of UTF8 to UTF8");
	return true;
}

static bool test_plato_latin_cp850_utf8_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_latin_utf8 = base64_decode_data_blob(plato_latin_utf8_base64);
	DATA_BLOB plato_latin_utf16le = base64_decode_data_blob(plato_latin_utf16le_base64);
	DATA_BLOB plato_latin_output;
	DATA_BLOB plato_latin_output2;
	
	talloc_steal(tctx, plato_latin_utf8.data);
	talloc_steal(tctx, plato_latin_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "CP850", "UTF8",
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "creating iconv handle");
		
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DOS, 
						    plato_latin_utf8.data, plato_latin_utf8.length, 
						    (void *)&plato_latin_output.data, &plato_latin_output.length) == false, 
		       "conversion of UTF8  latin charset greek to DOS charset CP850 should fail");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UNIX, 
						    plato_latin_utf8.data, plato_latin_utf8.length, 
						    (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF8 to (unix charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UTF8, 
						    plato_latin_utf8.data, plato_latin_utf8.length, 
						    (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF8 to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    plato_latin_utf16le.data, plato_latin_utf16le.length, 
						    (void *)&plato_latin_output.data, &plato_latin_output.length) == false, 	
		       "conversion of UTF16 latin charset greek to DOS charset CP850 should fail");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UNIX, 
						    plato_latin_utf16le.data, plato_latin_utf16le.length, 
						    (void *)&plato_latin_output.data, &plato_latin_output.length), 	
		       "conversion of UTF16 latin charset greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_UTF16LE, CH_UTF8, 
							  plato_latin_utf16le.data, plato_latin_utf16le.length, 
							  (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF16LE to UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_UTF8, CH_UTF16LE, 
							  plato_latin_output.data, plato_latin_output.length, 
							  (void *)&plato_latin_output2.data, &plato_latin_output2.length),
		       "round trip conversion of UTF16 latin charset greek to UTF8 and back again failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output2, plato_latin_utf16le,
				       "round trip conversion of UTF16 latin charset greek to UTF8 and back again failed");
	torture_assert_int_equal(tctx,
				 strlen_m_ext_handle(iconv_handle,
						     (const char *)plato_latin_output.data,
						     CH_UTF8, CH_UTF16LE),
				 plato_latin_output2.length / 2,
				 "checking strlen_m_ext of round trip conversion of UTF16 latin charset greek to UTF8 and back again");
	return true;
}

static bool test_utf8_nfc_to_nfd_overflow(struct torture_context *tctx)
{
	smb_iconv_t ic;
	DATA_BLOB utf8_nfc_blob;
	DATA_BLOB utf8_nfd_blob;
	DATA_BLOB src_blob;
	DATA_BLOB blob;
	size_t nconv;
	const char *src = NULL;
	char *dst = NULL;
	size_t dst_left;
	size_t srclen;
	bool ret = true;

	ic = smb_iconv_open("UTF8-NFD", "UTF8-NFC");
	torture_assert_goto(tctx, ic != (smb_iconv_t)-1, ret, done,
			    "creating iconv handle\n");

	utf8_nfc_blob = base64_decode_data_blob_talloc(tctx, utf8_nfc_base64);
	torture_assert_not_null_goto(tctx, utf8_nfc_blob.data, ret, done,
				     "OOM\n");

	utf8_nfd_blob = base64_decode_data_blob_talloc(tctx, utf8_nfd_base64);
	torture_assert_not_null_goto(tctx, utf8_nfd_blob.data, ret, done,
				     "OOM\n");

	blob = data_blob_talloc_zero(tctx, 255);
	torture_assert_not_null_goto(tctx, blob.data, ret, done, "OOM\n");

	/*
	 * Unfortunately the current implementation that performs the conversion
	 * (using libicu) returns EINVAL if the result buffer is too small, not
	 * E2BIG like iconv().
	 */

	src = "foo";
	srclen = 3;
	dst = (char *)blob.data;
	dst_left = 0;
	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_int_equal_goto(tctx, nconv, -1, ret, done,
				      "smb_iconv failed\n");
	torture_assert_errno_equal_goto(tctx, EINVAL, ret, done,
					"Wrong errno\n");

	src = "foo";
	srclen = 3;
	dst = (char *)blob.data;
	dst_left = 1;
	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_int_equal_goto(tctx, nconv, -1, ret, done,
				      "smb_iconv failed\n");
	torture_assert_errno_equal_goto(tctx, EINVAL, ret, done,
					"Wrong errno\n");

	src = "foo";
	srclen = 3;
	dst = (char *)blob.data;
	dst_left = 2;
	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_int_equal_goto(tctx, nconv, -1, ret, done,
				      "smb_iconv failed\n");
	torture_assert_errno_equal_goto(tctx, EINVAL, ret, done,
					"Wrong errno\n");

	src_blob = data_blob_const("foo", 3);
	src = (const char *)src_blob.data;
	srclen = src_blob.length;
	dst = (char *)blob.data;
	dst_left = 3;
	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_int_equal_goto(tctx, nconv, 3, ret, done,
				      "smb_iconv failed\n");

	blob.length = nconv;
	torture_assert_data_blob_equal(tctx,
				       src_blob,
				       blob,
				       "Conversion failed\n");

	src_blob = data_blob_const("foo", 4);
	src = (const char *)src_blob.data;
	srclen = src_blob.length;
	dst = (char *)blob.data;
	dst_left = 4;
	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_int_equal_goto(tctx, nconv, 4, ret, done,
				      "smb_iconv failed\n");

	blob.length = nconv;
	torture_assert_data_blob_equal(tctx,
				       src_blob,
				       blob,
				       "Conversion failed\n");

done:
	return ret;
}

static bool test_utf8_nfc_to_nfd(struct torture_context *tctx)
{
	smb_iconv_t ic;
	DATA_BLOB utf8_nfc_blob;
	DATA_BLOB utf8_nfd_blob;
	DATA_BLOB blob;
	size_t nconv;
	const char *src = NULL;
	char *dst = NULL;
	size_t dst_left;
	size_t srclen;
	bool ret = true;

	ic = smb_iconv_open("UTF8-NFD", "UTF8-NFC");
	torture_assert_goto(tctx, ic != (smb_iconv_t)-1, ret, done,
			    "creating iconv handle\n");

	utf8_nfc_blob = base64_decode_data_blob_talloc(tctx, utf8_nfc_base64);
	torture_assert_not_null_goto(tctx, utf8_nfc_blob.data, ret, done,
				     "OOM\n");

	utf8_nfd_blob = base64_decode_data_blob_talloc(tctx, utf8_nfd_base64);
	torture_assert_not_null_goto(tctx, utf8_nfd_blob.data, ret, done,
				     "OOM\n");

	blob = data_blob_talloc_zero(tctx, 255);
	torture_assert_not_null_goto(tctx, blob.data, ret, done, "OOM\n");

	dst = (char *)blob.data;
	dst_left = blob.length;
	src = (const char *)utf8_nfc_blob.data;
	srclen = strlen(src);

	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_goto(tctx, nconv != (size_t)-1, ret, done,
			    "smb_iconv failed\n");

	blob.length = nconv + 1; /* +1 for the trailing zero */
	torture_assert_data_blob_equal(tctx,
				       blob,
				       utf8_nfd_blob,
				       "Conversion failed\n");

done:
	return ret;
}

static bool test_utf8_nfd_to_nfc(struct torture_context *tctx)
{
	smb_iconv_t ic;
	DATA_BLOB utf8_nfc_blob;
	DATA_BLOB utf8_nfd_blob;
	DATA_BLOB blob;
	size_t nconv;
	const char *src = NULL;
	char *dst = NULL;
	size_t dst_left;
	size_t srclen;
	bool ret = true;

	ic = smb_iconv_open("UTF8-NFC", "UTF8-NFD");
	torture_assert_goto(tctx, ic != (smb_iconv_t)-1, ret, done,
			    "creating iconv handle\n");

	utf8_nfc_blob = base64_decode_data_blob_talloc(tctx, utf8_nfc_base64);
	torture_assert_not_null_goto(tctx, utf8_nfc_blob.data, ret, done,
				     "OOM\n");

	utf8_nfd_blob = base64_decode_data_blob_talloc(tctx, utf8_nfd_base64);
	torture_assert_not_null_goto(tctx, utf8_nfd_blob.data, ret, done,
				     "OOM\n");

	blob = data_blob_talloc_zero(tctx, 255);
	torture_assert_not_null_goto(tctx, blob.data, ret, done, "OOM\n");

	dst = (char *)blob.data;
	dst_left = blob.length;
	src = (const char *)utf8_nfd_blob.data;
	srclen = strlen(src);

	nconv = smb_iconv(ic,
			  &src,
			  &srclen,
			  &dst,
			  &dst_left);
	torture_assert_goto(tctx, nconv != (size_t)-1, ret, done,
			    "smb_iconv failed\n");

	blob.length = nconv + 1; /* +1 for the trailing zero */
	torture_assert_data_blob_equal(tctx,
				       blob,
				       utf8_nfc_blob,
				       "Conversion failed\n");

done:
	return ret;
}

static bool test_gd_case_utf8_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB gd_utf8 = base64_decode_data_blob(gd_utf8_base64);
	DATA_BLOB gd_utf8_upper = base64_decode_data_blob(gd_utf8_upper_base64);
	DATA_BLOB gd_utf8_lower = base64_decode_data_blob(gd_utf8_lower_base64);
	char *gd_lower, *gd_upper;
	talloc_steal(tctx, gd_utf8.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ASCII", "UTF8",
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting utf8 iconv handle");

	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, (const char *)gd_utf8.data),
		       "GD's name has an upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, (const char *)gd_utf8.data),
		       "GD's name has an lower case character");
	gd_lower = strlower_talloc_handle(iconv_handle, tctx, (const char *)gd_utf8.data);
	torture_assert(tctx, gd_lower, "failed to convert GD's name into lower case");
	torture_assert_data_blob_equal(tctx, data_blob_string_const(gd_lower), gd_utf8_lower,
				       "convert GD's name into lower case");
	gd_upper = strupper_talloc_n_handle(iconv_handle, tctx, (const char *)gd_utf8.data, gd_utf8.length);
	torture_assert(tctx, gd_lower, "failed to convert GD's name into upper case");
	torture_assert_data_blob_equal(tctx, data_blob_string_const(gd_upper), gd_utf8_upper,
				       "convert GD's name into upper case");

	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, gd_upper),
		       "upper case name has an upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, gd_lower),
		       "lower case name has an lower case character");
	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, gd_lower) == false,
		       "lower case name has no upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, gd_upper) == false,
		       "upper case name has no lower case character");

	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, (const char *)gd_utf8.data,
						 gd_upper) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, (const char *)gd_utf8.data,
						 gd_lower) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, gd_upper,
						 gd_lower) == 0,
		       "case insensitive comparison upper/lower");

	/* This string isn't different in length upper/lower */
	torture_assert(tctx, strncasecmp_m_handle(iconv_handle, (const char *)gd_utf8.data,
						  gd_upper, gd_utf8.length) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strncasecmp_m_handle(iconv_handle, (const char *)gd_utf8.data,
						 gd_lower, gd_utf8.length) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strncasecmp_m_handle(iconv_handle, gd_upper,
						 gd_lower, gd_utf8.length) == 0,
		       "case insensitive comparison upper/lower");

	data_blob_free(&gd_utf8);
	data_blob_free(&gd_utf8_upper);
	data_blob_free(&gd_utf8_lower);

	return true;
}

static bool test_gd_case_cp850_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB gd_cp850 = base64_decode_data_blob(gd_cp850_base64);
	DATA_BLOB gd_cp850_upper = base64_decode_data_blob(gd_cp850_upper_base64);
	DATA_BLOB gd_cp850_lower = base64_decode_data_blob(gd_cp850_lower_base64);
	char *gd_lower, *gd_upper;
	talloc_steal(tctx, gd_cp850.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ASCII", "CP850",
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting cp850 iconv handle");

	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, (const char *)gd_cp850.data),
		       "GD's name has an upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, (const char *)gd_cp850.data),
		       "GD's name has an lower case character");
	gd_lower = strlower_talloc_handle(iconv_handle, tctx, (const char *)gd_cp850.data);
	torture_assert(tctx, gd_lower, "failed to convert GD's name into lower case");
	torture_assert_data_blob_equal(tctx, data_blob_string_const(gd_lower), gd_cp850_lower,
				       "convert GD's name into lower case");
	gd_upper = strupper_talloc_n_handle(iconv_handle, tctx, (const char *)gd_cp850.data, gd_cp850.length);
	torture_assert(tctx, gd_lower, "failed to convert GD's name into upper case");
	torture_assert_data_blob_equal(tctx, data_blob_string_const(gd_upper), gd_cp850_upper,
				       "convert GD's name into upper case");

	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, gd_upper),
		       "upper case name has an upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, gd_lower),
		       "lower case name has an lower case character");
	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, gd_lower) == false,
		       "lower case name has no upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, gd_upper) == false,
		       "upper case name has no lower case character");

	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, (const char *)gd_cp850.data,
						 gd_upper) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, (const char *)gd_cp850.data,
						 gd_lower) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, gd_upper,
						 gd_lower) == 0,
		       "case insensitive comparison upper/lower");

	/* This string isn't different in length upper/lower */
	torture_assert(tctx, strncasecmp_m_handle(iconv_handle, (const char *)gd_cp850.data,
						 gd_upper, gd_cp850.length) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strncasecmp_m_handle(iconv_handle, (const char *)gd_cp850.data,
						 gd_lower, gd_cp850.length) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strncasecmp_m_handle(iconv_handle, gd_upper,
						 gd_lower, gd_cp850.length) == 0,
		       "case insensitive comparison upper/lower");

	data_blob_free(&gd_cp850);
	data_blob_free(&gd_cp850_upper);
	data_blob_free(&gd_cp850_lower);

	return true;
}

static bool test_plato_case_utf8_handle(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_utf8 = base64_decode_data_blob(plato_utf8_base64);
	char *plato_lower, *plato_upper;
	talloc_steal(tctx, plato_utf8.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ASCII", "UTF8",
						lpcfg_parm_bool(tctx->lp_ctx, NULL, "iconv", "use_builtin_handlers", true));
	torture_assert(tctx, iconv_handle, "getting utf8 iconv handle");

	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, (const char *)plato_utf8.data),
		       "PLATO's apology has an upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, (const char *)plato_utf8.data),
		       "PLATO's apology has an lower case character");
	plato_lower = strlower_talloc_handle(iconv_handle, tctx, (const char *)plato_utf8.data);
	torture_assert(tctx, plato_lower, "failed to convert PLATO's apology into lower case");
	plato_upper = strupper_talloc_n_handle(iconv_handle, tctx, (const char *)plato_utf8.data, plato_utf8.length);
	torture_assert(tctx, plato_lower, "failed to convert PLATO's apology into upper case");

	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, plato_upper),
		       "upper case string has an upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, plato_lower),
		       "lower case string has an lower case character");
	torture_assert(tctx,
		       strhasupper_handle(iconv_handle, plato_lower) == false,
		       "lower case string has no upper case character");
	torture_assert(tctx,
		       strhaslower_handle(iconv_handle, plato_upper) == false,
		       "upper case string has no lower case character");

	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, (const char *)plato_utf8.data,
						 plato_upper) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, (const char *)plato_utf8.data,
						 plato_lower) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strcasecmp_m_handle(iconv_handle, plato_upper,
						 plato_lower) == 0,
		       "case insensitive comparison upper/lower");
	return true;
}

static bool test_gd(struct torture_context *tctx)
{
	DATA_BLOB gd_utf8 = base64_decode_data_blob(gd_utf8_base64);
	DATA_BLOB gd_cp850 = base64_decode_data_blob(gd_cp850_base64);
	DATA_BLOB gd_iso8859_1 = base64_decode_data_blob(gd_iso8859_1_base64);
	DATA_BLOB gd_utf16le = base64_decode_data_blob(gd_utf16le_base64);
	DATA_BLOB gd_output;
	size_t saved_len;

	talloc_steal(tctx, gd_utf8.data);
	talloc_steal(tctx, gd_cp850.data);
	talloc_steal(tctx, gd_iso8859_1.data);
	talloc_steal(tctx, gd_utf16le.data);

	torture_assert(tctx, convert_string_talloc(tctx, CH_UTF8, CH_UTF8,
						   gd_utf8.data, gd_utf8.length,
						   (void *)&gd_output.data, &gd_output.length),
		       "conversion from UTF8 to utf8 charset");
	saved_len = gd_output.length;

	torture_assert(tctx, convert_string_error(CH_UTF8, CH_UTF8,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length),
		       "conversion from UTF8 to utf8 charset");

	/* Short output handling confirmation */
	gd_output.length = 1;
	torture_assert(tctx, convert_string_error(CH_UTF8, CH_UTF8,
							 gd_utf8.data, gd_utf8.length,
							 (void *)gd_output.data, gd_output.length,
							 &gd_output.length) == false,
		       "conversion from UTF8 to any utf8 charset should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to utf8 charset should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	torture_assert_data_blob_equal(tctx, gd_output, data_blob_string_const("G"), "conversion from UTF8 to utf8 charset incorrect");

#if 0 /* This currently fails as we just copy like-for-like character conversions */
	/* Short output handling confirmation */
	gd_output.length = 2;
	torture_assert(tctx, convert_string_error(CH_UTF8, CH_UTF8,
						  gd_utf8.data, gd_utf8.length,
						  (void *)gd_output.data, gd_output.length,
						  &gd_output.length) == false,
		       "conversion from UTF8 to utf8 charset should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF8 to utf8 charset should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");

	/* Short input handling confirmation */
	gd_output.length = saved_len;
	torture_assert(tctx, convert_string_error(CH_UTF8, CH_UTF8,
						  gd_utf8.data, 2,
						  (void *)gd_output.data, gd_output.length,
						  &gd_output.length) == false,
		       "conversion from UTF8 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, EILSEQ, "conversion from short UTF8 to UTF8 should fail EINVAL");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
#endif

	/* Short output handling confirmation */
	gd_output.length = 1;
	torture_assert(tctx, convert_string_error(CH_UTF16LE, CH_UTF8,
						  gd_utf16le.data, gd_utf16le.length,
						  (void *)gd_output.data, gd_output.length,
						  &gd_output.length) == false,
		       "conversion from UTF16 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16 to UTF8 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");
	torture_assert_data_blob_equal(tctx, gd_output, data_blob_string_const("G"), "conversion from UTF16 to UTF8 incorrect");

	/* Short output handling confirmation */
	gd_output.length = 3;
	torture_assert(tctx, convert_string_error(CH_UTF16LE, CH_UTF8,
						  gd_utf16le.data, gd_utf16le.length,
						  (void *)gd_output.data, gd_output.length,
						  &gd_output.length) == false,
		       "conversion from UTF16 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, E2BIG, "conversion from UTF16 to UTF8 should fail E2BIG");
	torture_assert_int_equal(tctx, gd_output.length, 3, "Should get 3 bytes output for UTF8");

	/* Short input handling confirmation */
	gd_output.length = saved_len;
	torture_assert(tctx, convert_string_error(CH_UTF16LE, CH_UTF8,
						  gd_utf16le.data, 3,
						  (void *)gd_output.data, gd_output.length,
						  &gd_output.length) == false,
		       "conversion from UTF16 to UTF8 should fail due to too short");
	torture_assert_errno_equal(tctx, EINVAL, "conversion from short UTF16 to UTF8 should fail EINVAL");
	torture_assert_int_equal(tctx, gd_output.length, 1, "Should only get 1 char of output");

	return true;
}

static bool test_plato(struct torture_context *tctx)
{
	DATA_BLOB plato_utf8 = base64_decode_data_blob(plato_utf8_base64);
	DATA_BLOB plato_utf16le = base64_decode_data_blob(plato_utf16le_base64);
	DATA_BLOB plato_output;
	DATA_BLOB plato_output2;

	talloc_steal(tctx, plato_utf8.data);
	talloc_steal(tctx, plato_utf16le.data);

	torture_assert(tctx, convert_string_talloc(tctx,
						   CH_UTF8, CH_UTF16LE,
						   plato_utf8.data, plato_utf8.length,
						   (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le, "conversion from UTF8 to UTF16LE incorrect");

	torture_assert_int_equal(tctx,
				 strlen_m_ext((const char *)plato_utf8.data,
					      CH_UTF8, CH_UTF16LE),
				 plato_output.length / 2,
				 "checking strlen_m_ext of conversion of UTF8 to UTF16LE");

	memset(plato_output.data, '\0', plato_output.length);
	torture_assert(tctx, convert_string_error(CH_UTF8, CH_UTF16LE,
						  plato_utf8.data, plato_utf8.length,
						  (void *)plato_output.data, plato_output.length,
						  &plato_output.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf16le, "conversion from UTF8 to UTF16LE incorrect");

	torture_assert(tctx, convert_string_talloc(tctx,
						   CH_UTF16LE, CH_UTF8,
						   plato_output.data, plato_output.length,
						   (void *)&plato_output2.data, &plato_output2.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf8, "conversion from UTF8 to UTF16LE incorrect");

	memset(plato_output2.data, '\0', plato_output2.length);
	torture_assert(tctx, convert_string_error(CH_UTF16LE, CH_UTF8,
						  plato_output.data, plato_output.length,
						  (void *)plato_output2.data, plato_output2.length, &plato_output2.length),
		       "conversion of UTF8 ancient greek to UTF16 failed");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf8, "conversion from UTF8 to UTF16LE incorrect");

	torture_assert(tctx, convert_string_talloc(tctx,
						   CH_UTF8, CH_UTF8,
						   plato_utf8.data, plato_utf8.length,
						   (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF8 to UTF8");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8,
				       "conversion of UTF8 to UTF8");
	torture_assert_int_equal(tctx,
				 strlen_m_ext((const char *)plato_utf8.data,
					      CH_UTF8, CH_UTF8),
				 plato_output.length,
				 "checking strlen_m_ext of conversion of UTF8 to UTF8");
	memset(plato_output.data, '\0', plato_output.length);
	torture_assert(tctx, convert_string_error(CH_UTF8, CH_UTF8,
						  plato_utf8.data, plato_utf8.length,
						  (void *)plato_output.data, plato_output.length,
						  &plato_output.length),
		       "conversion of UTF8 to UTF8");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8,
				       "conversion of UTF8 to UTF8");

	memset(plato_output.data, '\0', plato_output.length);
	torture_assert(tctx, convert_string_error(CH_UTF8, CH_DOS,
						  plato_utf8.data, plato_utf8.length,
						  (void *)plato_output.data, plato_output.length,
						  &plato_output.length) == false,
		       "conversion of UTF8 to any dos charset should fail");
	torture_assert_errno_equal(tctx,  EILSEQ, "conversion of UTF16 ancient greek to any DOS charset should fail EILSEQ");

	torture_assert(tctx, convert_string_talloc(tctx,
						   CH_UTF8, CH_DOS,
						   plato_utf8.data, plato_utf8.length,
						   (void *)&plato_output.data, &plato_output.length) == false,
		       "conversion of UTF8 ancient greek to any DOS charset should fail");

	/* Allocate only enough space for a partial conversion */
	plato_output = data_blob_talloc(tctx, NULL, 9);
	torture_assert(tctx, convert_string_error(CH_UTF16LE, CH_UTF8,
						  plato_utf16le.data, plato_utf16le.length,
						  (void *)plato_output.data, plato_output.length,
						  &plato_output.length) == false,
		       "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_errno_equal(tctx,  E2BIG, "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_int_equal(tctx, plato_output.length, 8,
				 "conversion of UTF16 ancient greek to UTF8 should stop on multibyte boundary");

	plato_output = data_blob_talloc(tctx, NULL, 2);
	torture_assert(tctx, convert_string_error(CH_UTF16LE, CH_UTF8,
						  plato_utf16le.data, plato_utf16le.length,
						  (void *)plato_output.data, plato_output.length,
						  &plato_output.length) == false,
		       "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_errno_equal(tctx,  E2BIG, "conversion of UTF16 ancient greek to UTF8 should fail, not enough space");
	torture_assert_int_equal(tctx, plato_output.length, 0,
				 "conversion of UTF16 ancient greek to UTF8 should stop on multibyte boundary");


	return true;
}

static bool test_plato_latin(struct torture_context *tctx)
{
	DATA_BLOB plato_latin_utf8 = base64_decode_data_blob(plato_latin_utf8_base64);
	DATA_BLOB plato_latin_utf16le = base64_decode_data_blob(plato_latin_utf16le_base64);
	DATA_BLOB plato_latin_output;

	talloc_steal(tctx, plato_latin_utf8.data);
	talloc_steal(tctx, plato_latin_utf16le.data);

	torture_assert(tctx, convert_string_talloc(tctx,
						    CH_UTF16LE, CH_UTF8,
						    plato_latin_utf16le.data, plato_latin_utf16le.length,
						    (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF16 to UTF8 incorrect");

	torture_assert_int_equal(tctx,
				 strlen_m_ext((const char *)plato_latin_output.data,
					      CH_UTF8, CH_UTF16LE),
				 plato_latin_utf16le.length / 2,
				 "checking strlen_m_ext UTF16 latin charset greek to UTF8");
	torture_assert(tctx, convert_string_talloc(tctx,
						    CH_UTF8, CH_UTF16LE,
						    plato_latin_utf8.data, plato_latin_utf8.length,
						    (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to UTF16LE failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf16le, "conversion from UTF8 to UTF16LE incorrect");

	return true;
}

static bool test_gd_case(struct torture_context *tctx)
{
	DATA_BLOB gd_utf8 = base64_decode_data_blob(gd_utf8_base64);
	char *gd_unix;
	size_t gd_size;
	char *gd_lower, *gd_upper;
	talloc_steal(tctx, gd_utf8.data);

	torture_assert(tctx, convert_string_talloc(tctx, CH_UTF8, CH_UNIX,
						   gd_utf8.data, gd_utf8.length,
						   (void *)&gd_unix, &gd_size),
		       "conversion of unix charset to UTF8");

	gd_lower = strlower_talloc(tctx, gd_unix);
	torture_assert(tctx, gd_lower, "failed to convert GD's name into lower case");
	gd_upper = strupper_talloc_n(tctx, gd_unix, gd_size);
	torture_assert(tctx, gd_lower, "failed to convert GD's name into upper case");

	torture_assert(tctx,
		       strhasupper(gd_unix),
		       "GD's name has an upper case character");
	torture_assert(tctx,
		       strhaslower(gd_unix),
		       "GD's name has an lower case character");
	torture_assert(tctx,
		       strhasupper(gd_upper),
		       "upper case name has an upper case character");
	torture_assert(tctx,
		       strhaslower(gd_lower),
		       "lower case name has an lower case character");
	torture_assert(tctx,
		       strhasupper(gd_lower) == false,
		       "lower case name has no upper case character");
	torture_assert(tctx,
		       strhaslower(gd_upper) == false,
		       "upper case name has no lower case character");

	torture_assert(tctx, strcasecmp_m(gd_unix,
						 gd_upper) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strcasecmp_m(gd_unix,
						 gd_lower) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strcasecmp_m(gd_upper,
						 gd_lower) == 0,
		       "case insensitive comparison upper/lower");

	/* This string isn't different in length upper/lower, but just check the first 5 chars */
	torture_assert(tctx, strncasecmp_m(gd_unix,
						  gd_upper, 5) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strncasecmp_m(gd_unix,
						 gd_lower, 5) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strncasecmp_m(gd_upper,
						 gd_lower, 5) == 0,
		       "case insensitive comparison upper/lower");
	return true;
}

static bool test_plato_case(struct torture_context *tctx)
{
	DATA_BLOB plato_utf8 = base64_decode_data_blob(plato_utf8_base64);
	char *plato_unix;
	size_t plato_length;
	char *plato_lower, *plato_upper;
	talloc_steal(tctx, plato_utf8.data);

	torture_assert(tctx, convert_string_talloc(tctx, CH_UTF8, CH_UNIX,
						   plato_utf8.data, plato_utf8.length,
						   (void *)&plato_unix, &plato_length),
		       "conversion of unix charset to UTF8");

	torture_assert(tctx,
		       strhasupper(plato_unix),
		       "PLATO's apology has an upper case character");
	torture_assert(tctx,
		       strhaslower(plato_unix),
		       "PLATO's apology has an lower case character");
	plato_lower = strlower_talloc(tctx, plato_unix);
	torture_assert(tctx, plato_lower, "failed to convert PLATO's apology into lower case");
	plato_upper = strupper_talloc_n(tctx, plato_unix, plato_utf8.length);
	torture_assert(tctx, plato_lower, "failed to convert PLATO's apology into upper case");

	torture_assert(tctx,
		       strhasupper(plato_upper),
		       "upper case string has an upper case character");
	torture_assert(tctx,
		       strhaslower(plato_lower),
		       "lower case string has an lower case character");
	torture_assert(tctx,
		       strhasupper(plato_lower) == false,
		       "lower case string has no upper case character");
	torture_assert(tctx,
		       strhaslower(plato_upper) == false,
		       "upper case string has no lower case character");

	torture_assert(tctx, strcasecmp_m(plato_unix,
						 plato_upper) == 0,
		       "case insensitive comparison orig/upper");
	torture_assert(tctx, strcasecmp_m(plato_unix,
						 plato_lower) == 0,
		       "case insensitive comparison orig/lower");
	torture_assert(tctx, strcasecmp_m(plato_upper,
						 plato_lower) == 0,
		       "case insensitive comparison upper/lower");
	return true;
}

struct torture_suite *torture_local_convert_string_handle(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "convert_string_handle");
	torture_suite_add_simple_test(suite, "cp850 high points", test_cp850_high_points);

	torture_suite_add_simple_test(suite, "gd_ascii", test_gd_ascii_handle);
	torture_suite_add_simple_test(suite, "gd_minus_1", test_gd_minus_1_handle);
	torture_suite_add_simple_test(suite, "gd_iso8859_cp850", test_gd_iso8859_cp850_handle);
	torture_suite_add_simple_test(suite, "plato_english_iso8859_cp850", test_plato_english_iso8859_cp850_handle);
	torture_suite_add_simple_test(suite, "plato_english_minus_1", test_plato_english_minus_1_handle);
	torture_suite_add_simple_test(suite, "plato_cp850_utf8", test_plato_cp850_utf8_handle);
	torture_suite_add_simple_test(suite, "plato_minus_1", test_plato_minus_1_handle);
	torture_suite_add_simple_test(suite, "plato_latin_cp850_utf8", test_plato_latin_cp850_utf8_handle);
	torture_suite_add_simple_test(suite, "utf8-nfc-to-nfd", test_utf8_nfc_to_nfd);
	torture_suite_add_simple_test(suite, "utf8-nfc-to-nfd-overflow", test_utf8_nfc_to_nfd_overflow);
	torture_suite_add_simple_test(suite, "utf8-nfd-to-nfc", test_utf8_nfd_to_nfc);
	return suite;
}

struct torture_suite *torture_local_string_case_handle(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "string_case_handle");

	torture_suite_add_simple_test(suite, "gd_case_utf8", test_gd_case_utf8_handle);
	torture_suite_add_simple_test(suite, "gd_case_cp850", test_gd_case_cp850_handle);
	torture_suite_add_simple_test(suite, "plato_case_utf8", test_plato_case_utf8_handle);
	return suite;
}

struct torture_suite *torture_local_convert_string(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "convert_string");

	torture_suite_add_simple_test(suite, "gd", test_gd);
	torture_suite_add_simple_test(suite, "plato", test_plato);
	torture_suite_add_simple_test(suite, "plato_latin", test_plato_latin);
	return suite;
}

struct torture_suite *torture_local_string_case(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "string_case_handle");

	torture_suite_add_simple_test(suite, "gd_case", test_gd_case);
	torture_suite_add_simple_test(suite, "plato_case", test_plato_case);
	return suite;
}
