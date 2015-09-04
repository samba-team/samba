/*
   Unix SMB/CIFS implementation.
   Name mangling
   Copyright (C) Andrew Tridgell 1992-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Jeremy Allison 2007

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
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "mangle.h"
#include "util_tdb.h"
#include "lib/param/loadparm.h"

/* -------------------------------------------------------------------------- **
 * Other stuff...
 *
 * magic_char     - This is the magic char used for mangling.  It's
 *                  global.  There is a call to lp_mangling_char() in server.c
 *                  that is used to override the initial value.
 *
 * MANGLE_BASE    - This is the number of characters we use for name mangling.
 *
 * basechars      - The set characters used for name mangling.  This
 *                  is static (scope is this file only).
 *
 * mangle()       - Macro used to select a character from basechars (i.e.,
 *                  mangle(n) will return the nth digit, modulo MANGLE_BASE).
 *
 * chartest       - array 0..255.  The index range is the set of all possible
 *                  values of a byte.  For each byte value, the content is a
 *                  two nibble pair.  See BASECHAR_MASK below.
 *
 * ct_initialized - False until the chartest array has been initialized via
 *                  a call to init_chartest().
 *
 * BASECHAR_MASK  - Masks the upper nibble of a one-byte value.
 *
 * isbasecahr()   - Given a character, check the chartest array to see
 *                  if that character is in the basechars set.  This is
 *                  faster than using strchr_m().
 *
 */

static const char basechars[43]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-!@#$%";
#define MANGLE_BASE       (sizeof(basechars)/sizeof(char)-1)

#define mangle(V) ((char)(basechars[(V) % MANGLE_BASE]))
#define BASECHAR_MASK 0xf0
#define isbasechar(C) ( (chartest[ ((C) & 0xff) ]) & BASECHAR_MASK )

/* -------------------------------------------------------------------- */


/*******************************************************************
 Determine if a character is valid in a 8.3 name.
********************************************************************/

static const uint32_t valid_table[] = {
	0x00000000,0x2fff7bfa,0xefffffff,0xefffffff,0x00000001,0x0fffffee,
	0xffffffff,0xffffffff,0x00000000,0x00000000,0x00000000,0x01000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0xfffe0000,0xfffe03fb,
	0x000003ff,0x00000000,0xffff0002,0xffffffff,0x0002ffff,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x33210000,0x080d0063,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00400008,0x00000802,0x00000000,0x03ff03ff,0x000f0000,0x00000000,
	0x00140000,0x00000000,0xe402098d,0x20305fa1,0x00040000,0x00000cc3,
	0x000000cc,0x80000020,0x00000000,0x00000000,0x00040000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x000fffff,0x00000000,0x00000000,
	0x00000000,0x00000000,0x3999900f,0x99999939,0x00000804,0x00000000,
	0x00000000,0x300c0003,0x0000c8c0,0x00008000,0x00000060,0x00000000,
	0x00000005,0x0000a400,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0xa03fffef,0x00000000,0xfffffffe,0xffffffff,0x781fffff,0xfffffffe,
	0xffffffff,0x787fffff,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x02060000,
	0x00000000,0x00000000,0x00000000,0x000001f0,0x00000000,0x00000000,
	0x01102008,0x084008cc,0x00822600,0x78000000,0x7000c000,0x00000002,
	0x00002010,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x43f36f8b,0x9b462542,0xe3e0e82c,0x400a0004,0xdb365f65,0x04497977,
	0xe3f0ecd7,0x18c5603a,0x3403e60b,0x37518000,0x7eebe0c8,0x98698200,
	0x2d56ad48,0x8060e803,0xad93661c,0xc568c03a,0xc656aa60,0x02403f7e,
	0x146183cd,0x21751020,0x07122021,0x40bc3000,0x4562a624,0x0a3060a8,
	0x85740217,0x9c840402,0x14157ffb,0x11e27f34,0x22efb665,0x60ff1f75,
	0x38403a70,0x676336c3,0x20b24dd9,0x0fc946b0,0x4850bc98,0xa03f8638,
	0x98162388,0x5232be49,0xeba422ab,0xc72c00dd,0x26e1a1e7,0x8f0a841b,
	0x559e27eb,0x89bfc241,0x85480014,0x084d6361,0xaad07f0c,0x05cfff3e,
	0xa803ff1a,0x7b407a41,0x80024745,0x38eb0500,0x1005dc51,0x710c9b34,
	0x01000397,0xa4046366,0x005180d0,0x430ac000,0x30c89071,0x58000008,
	0xf7000ed9,0x00415f80,0x941000b0,0x62800018,0x09d00240,0x01568200,
	0x08015004,0x05101d10,0x001084c1,0x10504025,0x4d8a410f,0xa60d4009,
	0x914cab19,0x098121c0,0x0203c485,0x80000672,0x00080b04,0x0009141d,
	0x905c49c9,0x16900009,0x22200c65,0x24338412,0x47960c03,0x42250a04,
	0xd0880028,0x4f0c4900,0xd3aa14a2,0x3e87d830,0x1f618e04,0x41867ea4,
	0x2dbbc390,0x211857ad,0x2a48241e,0x4e041138,0x161b0a40,0x88400d60,
	0x9502020a,0x10608221,0x04000243,0x80001444,0x0c040000,0x70000000,
	0x00c11a06,0x0c00024a,0x00401a00,0x40451404,0xbdf30029,0x052b0a78,
	0xbfa0bba9,0x8379407c,0xe91d12fd,0xc5695bf6,0x444aeff6,0xff022115,
	0x402bed63,0x0242d033,0x00131000,0x5dca1b42,0x020000a0,0x2c61a703,
	0x8ff24880,0x00000284,0x100d5804,0x0048b200,0x20011894,0x37805004,
	0x684d3200,0x68be49ea,0x2e42184c,0x21c9a820,0x80b050b9,0xff7c001e,
	0x14e0849a,0x01e028c1,0xac49870e,0xdddb130f,0x89fbbe1a,0x51b2a2e2,
	0x32ca5522,0x928b3ec6,0x438f1dbf,0x32986703,0x73c03028,0xa9230811,
	0x3a65c000,0x04028fe3,0xa6252c4e,0x00a1bf3d,0x8cd43e3a,0x317c06c9,
	0xd52a00e0,0x0edf018b,0x8c22e34b,0xf0911183,0xa7287d94,0x40fbc9ac,
	0x07534484,0x44445a90,0x00013fc8,0xf5d40048,0xec5f7701,0x891dc442,
	0x49286b83,0xd2424109,0x59fe061d,0x3a221840,0x3b9fb7e4,0xc0eaf003,
	0x82021386,0xe4008980,0x10a1b200,0x0cc44b80,0x8944d309,0x48341faf,
	0x0c458259,0x0470420a,0x10c8a040,0x44503140,0x01004004,0x05408281,
	0x642c0108,0x1a056a30,0x051460a6,0x645690cf,0x31000021,0xcbf09c18,
	0x63e2e120,0x01b5104c,0x9a83538c,0x3281b8b2,0x0a84987a,0x0c0233e7,
	0xd038d6cd,0x9872e1b1,0xe2848a1e,0x0459c3f4,0x23c2439a,0xd3144845,
	0x36400292,0xffbd0241,0xe8f0eb09,0xa5d27dc0,0xd24bc242,0xd0afa47f,
	0x34a11aa0,0x0bd88247,0x651bc453,0xc83ad294,0x40c8001e,0x33140e06,
	0xb21f615f,0xc0d00088,0xa898a02a,0x166ba1c5,0x85b4af50,0x0604c08b,
	0x1e04f933,0xa251056e,0x76380400,0x73b8ed07,0x19324406,0xc8164081,
	0x63097c8a,0xaa042984,0xca9c1c24,0x27614e0e,0x830009d0,0xc10c0846,
	0x10816011,0x0908540d,0xcc0a000e,0x0c000514,0xa0440430,0x6784008b,
	0x8a195288,0x8b18865e,0x41602e59,0x9cbe8c10,0x895c6861,0x00089800,
	0x089a8100,0xc1900018,0xf4a14007,0x640d8505,0x0e4d314e,0xff0a4806,
	0x2ea81632,0x000b852e,0xca841810,0x696c0e20,0x16000032,0x0390d658,
	0x1a6851a0,0x11249000,0x432698e1,0x1fae5d52,0xae280fa0,0x5700fafb,
	0x99406408,0xc044c880,0xb1419005,0xa4c48424,0x603a1a34,0xc1949000,
	0x003a8246,0xc106180d,0x99100022,0x1511e050,0x00824157,0x022a041a,
	0x8930004f,0x446ad813,0xed228aa2,0x400511c0,0x01021000,0x31018808,
	0x02044620,0x0f08f800,0xa2008900,0x22020000,0x16108210,0x10400042,
	0x126052c0,0x200052f4,0x82308510,0x42021100,0x80b5430a,0xda2070e1,
	0x08012040,0xfc653500,0xab0419c1,0x62140286,0x00440087,0x42469085,
	0x0a85405c,0x33803207,0xb8c00400,0xc0d0ce30,0x0080c030,0x0da50508,
	0x00400a90,0x280c0200,0x40446705,0x41226429,0x000002e8,0x847c4664,
	0xde200002,0x4049861d,0xc0000a08,0x20010084,0x10108400,0x01c742cd,
	0xd52a703a,0x1d8f9968,0x3e12be50,0x81d9aef5,0x2412cec4,0x732e0828,
	0x4b3424ac,0xd41d020c,0x80002a02,0x08110097,0x114411c4,0x7d451786,
	0x5e4949dd,0x87914040,0xd8c4254c,0x491444ba,0xc8001b92,0x15800271,
	0x0c0000c1,0xc200096a,0x40024800,0xba493021,0x1c802080,0x1008e2ac,
	0x00341004,0x841400e3,0x20004020,0x14149810,0x04aa70c2,0x54208688,
	0x04130c62,0x20109180,0x02064082,0x54011c40,0xe4e90383,0x84802125,
	0x2810e433,0xe60944c0,0x81260a03,0x080112da,0x97906901,0xf8864001,
	0x0081e24d,0xa6510a0e,0x81ec011a,0x8441c600,0xb62eadb8,0x8741acef,
	0x4b028d54,0x02681161,0x2057bb60,0x043350a0,0xf7b4a8c0,0x01122402,
	0x20009ad3,0x00c82271,0x809e2081,0xe1800c8a,0x8151b009,0x40281031,
	0x89a52a0e,0x620e69b6,0xd1444425,0x4d548085,0x1fb12c75,0x862dd807,
	0x5841d97c,0x226e414e,0x9e088200,0xedb7f80d,0x75668c80,0x08149313,
	0xc8040e32,0x6ea6484e,0x66742c4a,0xba0126c0,0x185dd70c,0x00000000,
	0x00000000,0x00000000,0x00000000,0x05400000,0x813370a0,0x03a54f81,
	0x641055ec,0x2344c31a,0x00341462,0x1a090a43,0x13a5187b,0xa8480102,
	0xc5440440,0xe2dd8106,0x2d481af0,0x0416b626,0x6e405058,0x31128032,
	0x0c0007e4,0x420a8208,0x803b4840,0x87134860,0x3428850d,0xe5290319,
	0x870a2345,0x5c1825a9,0xd9c577a6,0x03e85e00,0xa7000081,0x41c6cd54,
	0xa2042800,0x2b0ab860,0xda9e0020,0x0e1a08ea,0x11c0427e,0x03768908,
	0x01058621,0x98a80004,0xc44846a0,0x20220d05,0x914854a2,0x28d78a01,
	0x00087898,0x31221605,0x08804340,0x06a2fa4e,0x92110814,0x9b142002,
	0x16432e52,0x90105000,0x85ba0041,0x20203042,0x07a84f0b,0x40802f08,
	0x1a930591,0x0601df50,0x3021a202,0x4e800630,0x04c80cc4,0x8001a004,
	0xd4316000,0x0a020880,0x00281c00,0x00418e18,0xca106ad0,0x4b00f210,
	0x1506274d,0x88900220,0x82a85a00,0x81504549,0x80002004,0x2c088804,
	0x000508d1,0x4ac48001,0x0062e0a0,0x0a42008e,0x6a8c3055,0xe0a5090e,
	0x42c42906,0x80b34814,0xb330803e,0x733c0102,0x700d1494,0x09400c20,
	0xc040301a,0xc094a451,0x05c88dca,0xa40c96c2,0x34040001,0x011000c8,
	0xa9cd550d,0x1cda2428,0x48370142,0x120f7a4d,0x452a32b4,0xd20531fb,
	0xdc44b894,0x45ca68d7,0x2ed15097,0x42081943,0x9d48d202,0xa0979840,
	0x064d5409,0x00000000,0x00000000,0x00000000,0x00000000,0x84800000,
	0x04215542,0x17001c06,0x61107624,0xb9ddff87,0x5c0a659f,0x3c11245d,
	0x005dadb0,0x00000000,0x00000000,0x00db28d0,0x02000422,0x44080108,
	0xac409804,0x90288d0a,0xe0018700,0x00310400,0x82211794,0x10540019,
	0x021a2cb2,0x40039c02,0x8804bd60,0x7900080c,0xba3c1628,0xcb088640,
	0x90807274,0x0000001e,0xd8000000,0x9c87e188,0x04124034,0x2791ae64,
	0xe6fbe86b,0x5366408f,0x537feea6,0xb5e4e3ab,0x0002869f,0x01228548,
	0x48004402,0x20a02116,0x02240004,0x00052080,0x01547e00,0x01ac162c,
	0x10852a84,0x05308c14,0xfdc3fbc3,0x906060fa,0x40336440,0x96901200,
	0x4e834b31,0x418200d4,0x1d6a0129,0x02802080,0x02ad8000,0x9f0c2691,
	0x67018044,0x0c24d96f,0x18d02910,0x50215001,0x04d01000,0x02017090,
	0x61c30148,0x01000132,0x07190088,0x05620802,0x4c0e0132,0xf0a10405,
	0x00000002,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00800000,0x035e8e8d,0x5a0421bd,0x11703488,0x00000026,
	0x10000000,0x8804c502,0xf801b815,0x25ed147c,0x3bb0ed60,0x1bd78589,
	0x1a627af3,0x0ac50d0c,0x524ae5d1,0x6b0d0490,0x5266a35c,0x16122b57,
	0x1101a872,0x00182949,0x10080948,0x886c6000,0x058f916e,0x39903012,
	0x49b0f840,0x001b88a0,0x00000000,0x00428500,0x98000058,0x7014ea04,
	0x611d1628,0x60005193,0x00a71a24,0x00000000,0x43c00000,0x10187120,
	0xa9270172,0x89066004,0x020cc022,0x40810900,0x8ca0602d,0x00000e34,
	0x00000000,0x11012100,0xd31a8011,0x0892ec4c,0x85000040,0x1806c7ac,
	0x0512e03e,0x00348000,0x80cec008,0x0a126d01,0x08568641,0x0027011e,
	0x083d3751,0x4e05e032,0x048401c0,0x01400081,0x00000000,0x00000000,
	0x00000000,0x00591aa0,0x882443c8,0xc8001d48,0x72030152,0x04059813,
	0x04008280,0x0d148a10,0x02088056,0x2704a040,0x4e000000,0x00000000,
	0x00000000,0xa3200000,0xa0ae1902,0xdf002660,0x7b17f010,0x3ad08121,
	0x00284180,0x48001003,0x8014cc00,0x00c414cf,0x30202000,0x00000001,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,
	0xffffffff,0xffffffff,0x00ffffff,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x000f0000,
	0x00000000,0x00000200,0x00000000,0x00000000,0x00000000,0x00000000,
	0x10000000,0x00000000,0xffffc000,0x00003fff,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
	0xfffffffe,0xffffffff,0x7fffffff,0xfffffffe,0xffffffff,0x00000000,
	0x00000000,0x0000003f
};

#if 0
/*
 * The following program regenerates the good old valid.dat. Try it
 * yourself :-)
 */
int main(void)
{
	int i;
	for (i=0; i<65536; i++) {
		char c = (valid_table[i/32] & (1<<(i%32))) ? 1 : 0;
		write(1, &c, 1);
	}
}
#endif

static bool isvalid83_w(smb_ucs2_t c)
{
	uint16_t idx = SVAL(&c, 0);
	return (valid_table[idx/32] & (1 << (idx%32))) != 0;
}

static NTSTATUS has_valid_83_chars(const smb_ucs2_t *s, bool allow_wildcards)
{
	if (!*s) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!allow_wildcards && ms_has_wild_w(s)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	while (*s) {
		if(!isvalid83_w(*s)) {
			return NT_STATUS_UNSUCCESSFUL;
		}
		s++;
	}

	return NT_STATUS_OK;
}

static NTSTATUS has_illegal_chars(const smb_ucs2_t *s, bool allow_wildcards)
{
	if (!allow_wildcards && ms_has_wild_w(s)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	while (*s) {
		if (*s <= 0x1f) {
			/* Control characters. */
			return NT_STATUS_UNSUCCESSFUL;
		}
		switch(*s) {
			case UCS2_CHAR('\\'):
			case UCS2_CHAR('/'):
			case UCS2_CHAR('|'):
			case UCS2_CHAR(':'):
				return NT_STATUS_UNSUCCESSFUL;
		}
		s++;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Duplicate string.
********************************************************************/

static smb_ucs2_t *strdup_w(const smb_ucs2_t *src)
{
	smb_ucs2_t *dest;
	size_t len = strlen_w(src);
	dest = SMB_MALLOC_ARRAY(smb_ucs2_t, len + 1);
	if (!dest) {
		DEBUG(0,("strdup_w: out of memory!\n"));
		return NULL;
	}

	memcpy(dest, src, len * sizeof(smb_ucs2_t));
	dest[len] = 0;
	return dest;
}

/* return False if something fail and
 * return 2 alloced unicode strings that contain prefix and extension
 */

static NTSTATUS mangle_get_prefix(const smb_ucs2_t *ucs2_string, smb_ucs2_t **prefix,
		smb_ucs2_t **extension, bool allow_wildcards)
{
	size_t ext_len;
	smb_ucs2_t *p;

	*extension = 0;
	*prefix = strdup_w(ucs2_string);
	if (!*prefix) {
		return NT_STATUS_NO_MEMORY;
	}
	if ((p = strrchr_w(*prefix, UCS2_CHAR('.')))) {
		ext_len = strlen_w(p+1);
		if ((ext_len > 0) && (ext_len < 4) && (p != *prefix) &&
		    (NT_STATUS_IS_OK(has_valid_83_chars(p+1,allow_wildcards)))) /* check extension */ {
			*p = 0;
			*extension = strdup_w(p+1);
			if (!*extension) {
				SAFE_FREE(*prefix);
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
	return NT_STATUS_OK;
}

/* ************************************************************************** **
 * Return NT_STATUS_UNSUCCESSFUL if a name is a special msdos reserved name.
 * or contains illegal characters.
 *
 *  Input:  fname - String containing the name to be tested.
 *
 *  Output: NT_STATUS_UNSUCCESSFUL, if the condition above is true.
 *
 *  Notes:  This is a static function called by is_8_3(), below.
 *
 * ************************************************************************** **
 */

static NTSTATUS is_valid_name(const smb_ucs2_t *fname, bool allow_wildcards, bool only_8_3)
{
	smb_ucs2_t *str, *p;
	size_t num_ucs2_chars;
	NTSTATUS ret = NT_STATUS_OK;

	if (!fname || !*fname)
		return NT_STATUS_INVALID_PARAMETER;

	/* . and .. are valid names. */
	if (strcmp_wa(fname, ".")==0 || strcmp_wa(fname, "..")==0)
		return NT_STATUS_OK;

	if (only_8_3) {
		ret = has_valid_83_chars(fname, allow_wildcards);
		if (!NT_STATUS_IS_OK(ret))
			return ret;
	}

	ret = has_illegal_chars(fname, allow_wildcards);
	if (!NT_STATUS_IS_OK(ret))
		return ret;

	/* Name can't end in '.' or ' ' */
	num_ucs2_chars = strlen_w(fname);
	if (fname[num_ucs2_chars-1] == UCS2_CHAR('.') || fname[num_ucs2_chars-1] == UCS2_CHAR(' ')) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	str = strdup_w(fname);

	/* Truncate copy after the first dot. */
	p = strchr_w(str, UCS2_CHAR('.'));
	if (p) {
		*p = 0;
	}

	strupper_w(str);
	p = &str[1];

	switch(str[0])
	{
	case UCS2_CHAR('A'):
		if(strcmp_wa(p, "UX") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('C'):
		if((strcmp_wa(p, "LOCK$") == 0)
		|| (strcmp_wa(p, "ON") == 0)
		|| (strcmp_wa(p, "OM1") == 0)
		|| (strcmp_wa(p, "OM2") == 0)
		|| (strcmp_wa(p, "OM3") == 0)
		|| (strcmp_wa(p, "OM4") == 0)
		)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('L'):
		if((strcmp_wa(p, "PT1") == 0)
		|| (strcmp_wa(p, "PT2") == 0)
		|| (strcmp_wa(p, "PT3") == 0)
		)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('N'):
		if(strcmp_wa(p, "UL") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('P'):
		if(strcmp_wa(p, "RN") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	default:
		break;
	}

	SAFE_FREE(str);
	return ret;
}

static NTSTATUS is_8_3_w(const smb_ucs2_t *fname, bool allow_wildcards)
{
	smb_ucs2_t *pref = 0, *ext = 0;
	size_t plen;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!fname || !*fname)
		return NT_STATUS_INVALID_PARAMETER;

	if (strlen_w(fname) > 12)
		return NT_STATUS_UNSUCCESSFUL;

	if (strcmp_wa(fname, ".") == 0 || strcmp_wa(fname, "..") == 0)
		return NT_STATUS_OK;

	/* Name cannot start with '.' */
	if (*fname == UCS2_CHAR('.'))
		return NT_STATUS_UNSUCCESSFUL;

	if (!NT_STATUS_IS_OK(is_valid_name(fname, allow_wildcards, True)))
		goto done;

	if (!NT_STATUS_IS_OK(mangle_get_prefix(fname, &pref, &ext, allow_wildcards)))
		goto done;
	plen = strlen_w(pref);

	if (strchr_wa(pref, '.'))
		goto done;
	if (plen < 1 || plen > 8)
		goto done;
	if (ext && (strlen_w(ext) > 3))
		goto done;

	ret = NT_STATUS_OK;

done:
	SAFE_FREE(pref);
	SAFE_FREE(ext);
	return ret;
}

static bool is_8_3(const char *fname, bool check_case, bool allow_wildcards,
		   const struct share_params *p)
{
	const char *f;
	smb_ucs2_t *ucs2name;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	size_t size;

	if (!fname || !*fname)
		return False;
	if ((f = strrchr(fname, '/')) == NULL)
		f = fname;
	else
		f++;

	if (strlen(f) > 12)
		return False;

	if (!push_ucs2_talloc(NULL, &ucs2name, f, &size)) {
		DEBUG(0,("is_8_3: internal error push_ucs2_talloc() failed!\n"));
		goto done;
	}

	ret = is_8_3_w(ucs2name, allow_wildcards);

done:
	TALLOC_FREE(ucs2name);

	if (!NT_STATUS_IS_OK(ret)) {
		return False;
	}

	return True;
}

/* -------------------------------------------------------------------------- **
 * Functions...
 */

/* ************************************************************************** **
 * Initialize the static character test array.
 *
 *  Input:  none
 *
 *  Output: none
 *
 *  Notes:  This function changes (loads) the contents of the <chartest>
 *          array.  The scope of <chartest> is this file.
 *
 * ************************************************************************** **
 */

static void init_chartest( void )
{
	const unsigned char *s;

	chartest = SMB_MALLOC_ARRAY(unsigned char, 256);

	SMB_ASSERT(chartest != NULL);
	memset(chartest, '\0', 256);

	for( s = (const unsigned char *)basechars; *s; s++ ) {
		chartest[*s] |= BASECHAR_MASK;
	}
}

/* ************************************************************************** **
 * Return True if the name *could be* a mangled name.
 *
 *  Input:  s - A path name - in UNIX pathname format.
 *
 *  Output: True if the name matches the pattern described below in the
 *          notes, else False.
 *
 *  Notes:  The input name is *not* tested for 8.3 compliance.  This must be
 *          done separately.  This function returns true if the name contains
 *          a magic character followed by excactly two characters from the
 *          basechars list (above), which in turn are followed either by the
 *          nul (end of string) byte or a dot (extension) or by a '/' (end of
 *          a directory name).
 *
 * ************************************************************************** **
 */

static bool is_mangled(const char *s, const struct share_params *p)
{
	char *magic;
	char magic_char;

	magic_char = lp_mangling_char(p);

	if (chartest == NULL) {
		init_chartest();
	}

	magic = strchr_m( s, magic_char );
	while( magic && magic[1] && magic[2] ) {         /* 3 chars, 1st is magic. */
		if( ('.' == magic[3] || '/' == magic[3] || !(magic[3]))          /* Ends with '.' or nul or '/' ?  */
				&& isbasechar( toupper_m(magic[1]) )           /* is 2nd char basechar?  */
				&& isbasechar( toupper_m(magic[2]) ) )         /* is 3rd char basechar?  */
			return( True );                           /* If all above, then true, */
		magic = strchr_m( magic+1, magic_char );      /*    else seek next magic. */
	}
	return( False );
}

/***************************************************************************
 Initializes or clears the mangled cache.
***************************************************************************/

static void mangle_reset( void )
{
	/* We could close and re-open the tdb here... should we ? The old code did
	   the equivalent... JRA. */
}

/***************************************************************************
 Add a mangled name into the cache.
 If the extension of the raw name maps directly to the
 extension of the mangled name, then we'll store both names
 *without* extensions.  That way, we can provide consistent
 reverse mangling for all names that match.  The test here is
 a bit more careful than the one done in earlier versions of
 mangle.c:

    - the extension must exist on the raw name,
    - it must be all lower case
    - it must match the mangled extension (to prove that no
      mangling occurred).
  crh 07-Apr-1998
**************************************************************************/

static void cache_mangled_name( const char mangled_name[13],
				const char *raw_name )
{
	TDB_DATA data_val;
	char mangled_name_key[13];
	char *s1 = NULL;
	char *s2 = NULL;

	/* If the cache isn't initialized, give up. */
	if( !tdb_mangled_cache )
		return;

	/* Init the string lengths. */
	strlcpy(mangled_name_key, mangled_name, sizeof(mangled_name_key));

	/* See if the extensions are unmangled.  If so, store the entry
	 * without the extension, thus creating a "group" reverse map.
	 */
	s1 = strrchr( mangled_name_key, '.' );
	if( s1 && (s2 = strrchr( raw_name, '.' )) ) {
		size_t i = 1;
		while( s1[i] && (tolower_m( s1[i] ) == s2[i]) )
			i++;
		if( !s1[i] && !s2[i] ) {
			/* Truncate at the '.' */
			*s1 = '\0';
			/*
			 * DANGER WILL ROBINSON - this
			 * is changing a const string via
			 * an aliased pointer ! Remember to
			 * put it back once we've used it.
			 * JRA
			 */
			*s2 = '\0';
		}
	}

	/* Allocate a new cache entry.  If the allocation fails, just return. */
	data_val = string_term_tdb_data(raw_name);
	if (tdb_store_bystring(tdb_mangled_cache, mangled_name_key, data_val, TDB_REPLACE) != 0) {
		DEBUG(0,("cache_mangled_name: Error storing entry %s -> %s\n", mangled_name_key, raw_name));
	} else {
		DEBUG(5,("cache_mangled_name: Stored entry %s -> %s\n", mangled_name_key, raw_name));
	}
	/* Restore the change we made to the const string. */
	if (s2) {
		*s2 = '.';
	}
}

/* ************************************************************************** **
 * Check for a name on the mangled name stack
 *
 *  Input:  s - Input *and* output string buffer.
 *	    maxlen - space in i/o string buffer.
 *  Output: True if the name was found in the cache, else False.
 *
 *  Notes:  If a reverse map is found, the function will overwrite the string
 *          space indicated by the input pointer <s>.  This is frightening.
 *          It should be rewritten to return NULL if the long name was not
 *          found, and a pointer to the long name if it was found.
 *
 * ************************************************************************** **
 */

static bool lookup_name_from_8_3(TALLOC_CTX *ctx,
				const char *in,
				char **out, /* talloced on the given context. */
				const struct share_params *p)
{
	TDB_DATA data_val;
	char *saved_ext = NULL;
	char *s = talloc_strdup(ctx, in);

	/* If the cache isn't initialized, give up. */
	if(!s || !tdb_mangled_cache ) {
		TALLOC_FREE(s);
		return False;
	}

	data_val = tdb_fetch_bystring(tdb_mangled_cache, s);

	/* If we didn't find the name *with* the extension, try without. */
	if(data_val.dptr == NULL || data_val.dsize == 0) {
		char *ext_start = strrchr( s, '.' );
		if( ext_start ) {
			if((saved_ext = talloc_strdup(ctx,ext_start)) == NULL) {
				TALLOC_FREE(s);
				return False;
			}

			*ext_start = '\0';
			data_val = tdb_fetch_bystring(tdb_mangled_cache, s);
			/*
			 * At this point s is the name without the
			 * extension. We re-add the extension if saved_ext
			 * is not null, before freeing saved_ext.
			 */
		}
	}

	/* Okay, if we haven't found it we're done. */
	if(data_val.dptr == NULL || data_val.dsize == 0) {
		TALLOC_FREE(saved_ext);
		TALLOC_FREE(s);
		return False;
	}

	/* If we *did* find it, we need to talloc it on the given ctx. */
	if (saved_ext) {
		*out = talloc_asprintf(ctx, "%s%s",
					(char *)data_val.dptr,
					saved_ext);
	} else {
		*out = talloc_strdup(ctx, (char *)data_val.dptr);
	}

	TALLOC_FREE(s);
	TALLOC_FREE(saved_ext);
	SAFE_FREE(data_val.dptr);

	return *out ? True : False;
}

/**
 Check if a string is in "normal" case.
**/

static bool strisnormal(const char *s, int case_default)
{
	if (case_default == CASE_UPPER)
		return(!strhaslower(s));

	return(!strhasupper(s));
}


/*****************************************************************************
 Do the actual mangling to 8.3 format.
*****************************************************************************/

static bool to_8_3(char magic_char, const char *in, char out[13], int default_case)
{
	int csum;
	char *p;
	char extension[4];
	char base[9];
	int baselen = 0;
	int extlen = 0;
	char *s = SMB_STRDUP(in);

	extension[0] = 0;
	base[0] = 0;

	if (!s) {
		return False;
	}

	p = strrchr(s,'.');
	if( p && (strlen(p+1) < (size_t)4) ) {
		bool all_normal = ( strisnormal(p+1, default_case) ); /* XXXXXXXXX */

		if( all_normal && p[1] != 0 ) {
			*p = 0;
			csum = str_checksum( s );
			*p = '.';
		} else
			csum = str_checksum(s);
	} else
		csum = str_checksum(s);

	if (!strupper_m( s )) {
		SAFE_FREE(s);
		return false;
	}

	if( p ) {
		if( p == s )
			strlcpy( extension, "___", 4);
		else {
			*p++ = 0;
			while( *p && extlen < 3 ) {
				if ( *p != '.') {
					extension[extlen++] = p[0];
				}
				p++;
			}
			extension[extlen] = 0;
		}
	}

	p = s;

	while( *p && baselen < 5 ) {
		if (isbasechar(*p)) {
			base[baselen++] = p[0];
		}
		p++;
	}
	base[baselen] = 0;

	csum = csum % (MANGLE_BASE*MANGLE_BASE);

	memcpy(out, base, baselen);
	out[baselen] = magic_char;
	out[baselen+1] = mangle( csum/MANGLE_BASE );
	out[baselen+2] = mangle( csum );

	if( *extension ) {
		out[baselen+3] = '.';
		strlcpy(&out[baselen+4], extension, 4);
	}

	SAFE_FREE(s);
	return True;
}

static bool must_mangle(const char *name,
			const struct share_params *p)
{
	smb_ucs2_t *name_ucs2 = NULL;
	NTSTATUS status;
	size_t converted_size;

	if (!push_ucs2_talloc(NULL, &name_ucs2, name, &converted_size)) {
		DEBUG(0, ("push_ucs2_talloc failed!\n"));
		return False;
	}
	status = is_valid_name(name_ucs2, False, False);
	TALLOC_FREE(name_ucs2);
	/* We return true if we *must* mangle, so if it's
	 * a valid name (status == OK) then we must return
	 * false. Bug #6939. */
	return !NT_STATUS_IS_OK(status);
}

/*****************************************************************************
 * Convert a filename to DOS format.  Return True if successful.
 *  Input:  in        Incoming name.
 *
 *          out       8.3 DOS name.
 *
 *          cache83 - If False, the mangled name cache will not be updated.
 *                    This is usually used to prevent that we overwrite
 *                    a conflicting cache entry prematurely, i.e. before
 *                    we know whether the client is really interested in the
 *                    current name.  (See PR#13758).  UKD.
 *
 * ****************************************************************************
 */

static bool hash_name_to_8_3(const char *in,
			char out[13],
			bool cache83,
			int default_case,
			const struct share_params *p)
{
	smb_ucs2_t *in_ucs2 = NULL;
	size_t converted_size;
	char magic_char;

	magic_char = lp_mangling_char(p);

	DEBUG(5,("hash_name_to_8_3( %s, cache83 = %s)\n", in,
		 cache83 ? "True" : "False"));

	if (!push_ucs2_talloc(NULL, &in_ucs2, in, &converted_size)) {
		DEBUG(0, ("push_ucs2_talloc failed!\n"));
		return False;
	}

	/* If it's already 8.3, just copy. */
	if (NT_STATUS_IS_OK(is_valid_name(in_ucs2, False, False)) &&
				NT_STATUS_IS_OK(is_8_3_w(in_ucs2, False))) {
		TALLOC_FREE(in_ucs2);
		strlcpy(out, in, 13);
		return True;
	}

	TALLOC_FREE(in_ucs2);
	if (!to_8_3(magic_char, in, out, default_case)) {
		return False;
	}

	cache_mangled_name(out, in);

	DEBUG(5,("hash_name_to_8_3(%s) ==> [%s]\n", in, out));
	return True;
}

/*
  the following provides the abstraction layer to make it easier
  to drop in an alternative mangling implementation
*/
static const struct mangle_fns mangle_hash_fns = {
	mangle_reset,
	is_mangled,
	must_mangle,
	is_8_3,
	lookup_name_from_8_3,
	hash_name_to_8_3
};

/* return the methods for this mangling implementation */
const struct mangle_fns *mangle_hash_init(void)
{
	mangle_reset();

	if (chartest == NULL) {
		init_chartest();
	}

	/* Create the in-memory tdb using our custom hash function. */
	tdb_mangled_cache = tdb_open_ex("mangled_cache", 1031, TDB_INTERNAL,
				(O_RDWR|O_CREAT), 0644, NULL, fast_string_hash);

	return &mangle_hash_fns;
}
