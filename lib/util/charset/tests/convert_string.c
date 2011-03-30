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
static const char *gd_cp850_base64 = "R4FudGhlciBEZXNjaG5lcg==";
static const char *gd_iso8859_1_base64 = "R/xudGhlciBEZXNjaG5lcg==";
static const char *gd_utf16le_base64 = "RwD8AG4AdABoAGUAcgAgAEQAZQBzAGMAaABuAGUAcgA=";

static bool test_gd_iso8859_cp850(struct torture_context *tctx)
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

	iconv_handle = get_iconv_testing_handle(tctx, "ISO8859-1", "CP850", "UTF8");
	torture_assert(tctx, iconv_handle, "getting iconv handle");
		
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DOS, 
						    gd_utf8.data, gd_utf8.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF8 to (dos charset) ISO8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF8 to (dos charset) ISO8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UNIX, 
						    gd_utf8.data, gd_utf8.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF8 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850, "conversion from UTF8 to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DISPLAY, 
						    gd_utf8.data, gd_utf8.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF8 to (display charset) UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF8 to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    gd_utf16le.data, gd_utf16le.length, 
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from UTF16LE to (dos charset) ISO8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF16LE to (dos charset) ISO8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    gd_output.data, gd_output.length, 
						    (void *)&gd_output2.data, &gd_output2.length),
		       "round trip conversion from (dos charset) ISO8859-1 back to UTF16LE");
	torture_assert_data_blob_equal(tctx, gd_output2, gd_utf16le,  "round trip conversion from (dos charset) ISO8859-1 back to UTF16LE");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UNIX, 
						    gd_utf16le.data, gd_utf16le.length, 
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from UTF16LE to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DISPLAY, 
						    gd_utf16le.data, gd_utf16le.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from UTF16LE to (display charset) UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF16LE to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_DOS, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length),
		       "conversion from (dos charset) ISO8859-1 to (dos charset) ISO8859-1");
	torture_assert_data_blob_equal(tctx, gd_output, gd_iso8859_1, "conversion from UTF16LE to (dos charset) ISO8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UNIX, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from (dos charset) ISO8859-1 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, gd_output, gd_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_DISPLAY, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from (dos charset) ISO8859-1 to (display charset) UTF8");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf8, "conversion from UTF16LE to (display charset) UTF8 incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    gd_iso8859_1.data, gd_iso8859_1.length, 
						    (void *)&gd_output.data, &gd_output.length), 
		       "conversion from (dos charset) ISO8859-1 to UTF16LE");
	torture_assert_data_blob_equal(tctx, gd_output, gd_utf16le, "conversion from (dos charset) ISO8859-1 to UTF16LE");
	return true;
}

static bool test_plato_english_iso8859_cp850(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_english_utf8 = data_blob_string_const(plato_english_ascii);
	DATA_BLOB plato_english_cp850 = plato_english_utf8;
	DATA_BLOB plato_english_iso8859_1 = plato_english_utf8;
	DATA_BLOB plato_english_utf16le = base64_decode_data_blob(plato_english_utf16le_base64);
	DATA_BLOB plato_english_output;
	DATA_BLOB plato_english_output2;
	
	talloc_steal(tctx, plato_english_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "ISO8859-1", "CP850", "UTF8");
	torture_assert(tctx, iconv_handle, "getting iconv handle");
		
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DOS, 
						    plato_english_utf8.data, plato_english_utf8.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF8 to (dos charset) ISO8859-1");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_iso8859_1, "conversion from UTF8 to (dos charset) ISO8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_UNIX, 
						    plato_english_utf8.data, plato_english_utf8.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF8 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_cp850, "conversion from UTF8 to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DISPLAY, 
						    plato_english_utf8.data, plato_english_utf8.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF8 to (display charset) UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF8 to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    plato_english_utf16le.data, plato_english_utf16le.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from UTF16LE to (dos charset) ISO8859-1");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_iso8859_1, "conversion from UTF16LE to (dos charset) ISO8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    plato_english_output.data, plato_english_output.length, 
						    (void *)&plato_english_output2.data, &plato_english_output2.length),
		       "round trip conversion from (dos charset) ISO8859-1 back to UTF16LE");
	torture_assert_data_blob_equal(tctx, plato_english_output2, plato_english_utf16le,  "round trip conversion from (dos charset) ISO8859-1 back to UTF16LE");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UNIX, 
						    plato_english_utf16le.data, plato_english_utf16le.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from UTF16LE to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DISPLAY, 
						    plato_english_utf16le.data, plato_english_utf16le.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from UTF16LE to (display charset) UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_DOS, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length),
		       "conversion from (dos charset) ISO8859-1 to (dos charset) ISO8859-1");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_iso8859_1, "conversion from UTF16LE to (dos charset) ISO8859-1 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UNIX, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from (dos charset) ISO8859-1 to (unix charset) CP850");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_cp850, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_DISPLAY, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from (dos charset) ISO8859-1 to (display charset) UTF8");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf8, "conversion from UTF16LE to (display charset) UTF8 incorrect");

	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_DOS, CH_UTF16LE, 
						    plato_english_iso8859_1.data, plato_english_iso8859_1.length, 
						    (void *)&plato_english_output.data, &plato_english_output.length), 
		       "conversion from (dos charset) ISO8859-1 to UTF16LE");
	torture_assert_data_blob_equal(tctx, plato_english_output, plato_english_utf16le, "conversion from (dos charset) ISO8859-1 to UTF16LE");
	return true;
}

static bool test_plato_cp850_utf8(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_utf8 = base64_decode_data_blob(plato_utf8_base64);
	DATA_BLOB plato_utf16le = base64_decode_data_blob(plato_utf16le_base64);
	DATA_BLOB plato_output;
	DATA_BLOB plato_output2;
	
	talloc_steal(tctx, plato_utf8.data);
	talloc_steal(tctx, plato_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "CP850", "UTF8", "UTF8");
	torture_assert(tctx, iconv_handle, "creating iconv handle");
		
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
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF8, CH_DISPLAY, 
						    plato_utf8.data, plato_utf8.length, 
						    (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF16 ancient greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF8 to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_DOS, 
						    plato_utf16le.data, plato_utf16le.length, 
						    (void *)&plato_output.data, &plato_output.length) == false, 	
		       "conversion of UTF16 ancient greek to DOS charset CP850 should fail");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
						    CH_UTF16LE, CH_UNIX, 
						    plato_utf16le.data, plato_utf16le.length, 
						    (void *)&plato_output.data, &plato_output.length), 	
		       "conversion of UTF16 ancient greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF16LE to (unix charset) CP850 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_UTF16LE, CH_DISPLAY, 
							  plato_utf16le.data, plato_utf16le.length, 
							  (void *)&plato_output.data, &plato_output.length),
		       "conversion of UTF16 ancient greek to display charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_output, plato_utf8, "conversion from UTF16LE to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_DISPLAY, CH_UTF16LE, 
							  plato_output.data, plato_output.length, 
							  (void *)&plato_output2.data, &plato_output2.length),
		       "round trip conversion of UTF16 ancient greek to display charset UTF8 and back again failed");
	torture_assert_data_blob_equal(tctx, plato_output2, plato_utf16le,
				       "round trip conversion of UTF16 ancient greek to display charset UTF8 and back again failed");
	return true;
}

static bool test_plato_latin_cp850_utf8(struct torture_context *tctx)
{
	struct smb_iconv_handle *iconv_handle;
	DATA_BLOB plato_latin_utf8 = base64_decode_data_blob(plato_latin_utf8_base64);
	DATA_BLOB plato_latin_utf16le = base64_decode_data_blob(plato_latin_utf16le_base64);
	DATA_BLOB plato_latin_output;
	DATA_BLOB plato_latin_output2;
	
	talloc_steal(tctx, plato_latin_utf8.data);
	talloc_steal(tctx, plato_latin_utf16le.data);

	iconv_handle = get_iconv_testing_handle(tctx, "CP850", "UTF8", "UTF8");
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
						    CH_UTF8, CH_DISPLAY, 
						    plato_latin_utf8.data, plato_latin_utf8.length, 
						    (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to unix charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF8 to (display charset) UTF8 incorrect");
	
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
							  CH_UTF16LE, CH_DISPLAY, 
							  plato_latin_utf16le.data, plato_latin_utf16le.length, 
							  (void *)&plato_latin_output.data, &plato_latin_output.length),
		       "conversion of UTF16 latin charset greek to display charset UTF8 failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output, plato_latin_utf8, "conversion from UTF16LE to (display charset) UTF8 incorrect");
	
	torture_assert(tctx, convert_string_talloc_handle(tctx, iconv_handle, 
							  CH_DISPLAY, CH_UTF16LE, 
							  plato_latin_output.data, plato_latin_output.length, 
							  (void *)&plato_latin_output2.data, &plato_latin_output2.length),
		       "round trip conversion of UTF16 latin charset greek to display charset UTF8 and back again failed");
	torture_assert_data_blob_equal(tctx, plato_latin_output2, plato_latin_utf16le,
				       "round trip conversion of UTF16 latin charset greek to display charset UTF8 and back again failed");
	return true;
}

struct torture_suite *torture_local_convert_string(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "convert_string_talloc");

	torture_suite_add_simple_test(suite, "gd_iso8859_cp850", test_gd_iso8859_cp850);
	torture_suite_add_simple_test(suite, "plato_english_iso8859_cp850", test_plato_english_iso8859_cp850);
	torture_suite_add_simple_test(suite, "plato_cp850_utf8", test_plato_cp850_utf8);
	torture_suite_add_simple_test(suite, "plato_latin_cp850_utf8", test_plato_latin_cp850_utf8);
	torture_suite_add_simple_test(suite, "plato_ascii_cp850_utf8", test_plato_latin_cp850_utf8);
	return suite;
}
