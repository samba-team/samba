/* 
 * Conversion table for CP850 charset also known as IBM850.
 *
 * Copyright (C) Alexander Bokovoy		2003
 *
 * Conversion tables are generated using GNU libc 2.2.5's 
 * localedata/charmaps/IBM850 table and source/script/gen-8bit-gap.sh script
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

static const uint16 to_ucs2[256] = {
 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
 0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
 0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
 0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
 0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
 0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
 0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
 0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
 0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
 0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x0192,
 0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
 0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0,
 0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510,
 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3,
 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4,
 0x00F0, 0x00D0, 0x00CA, 0x00CB, 0x00C8, 0x0131, 0x00CD, 0x00CE,
 0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580,
 0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE,
 0x00DE, 0x00DA, 0x00DB, 0x00D9, 0x00FD, 0x00DD, 0x00AF, 0x00B4,
 0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8,
 0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0,
};

static const struct charset_gap_table from_idx[] = {
    /* start, end, idx */
  { 0x0000, 0x007f, 0 },
  { 0x00a0, 0x00ff, -32 },
  { 0x0131, 0x0131, -81 },
  { 0x0192, 0x0192, -177 },
  { 0x2017, 0x2017, -7989 },
  { 0x2500, 0x2502, -9245 },
  { 0x250c, 0x251c, -9254 },
  { 0x2524, 0x2524, -9261 },
  { 0x252c, 0x252c, -9268 },
  { 0x2534, 0x2534, -9275 },
  { 0x253c, 0x253c, -9282 },
  { 0x2550, 0x256c, -9301 },
  { 0x2580, 0x2588, -9320 },
  { 0x2591, 0x2593, -9328 },
  { 0x25a0, 0x25a0, -9340 },
  { 0xffff, 0xffff, 0 }
};
static const unsigned char from_ucs2[] = {

  '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
  '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
  '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
  '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f',
  '\x20', '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27',
  '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f',
  '\x30', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37',
  '\x38', '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x3e', '\x3f',
  '\x40', '\x41', '\x42', '\x43', '\x44', '\x45', '\x46', '\x47',
  '\x48', '\x49', '\x4a', '\x4b', '\x4c', '\x4d', '\x4e', '\x4f',
  '\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57',
  '\x58', '\x59', '\x5a', '\x5b', '\x5c', '\x5d', '\x5e', '\x5f',
  '\x60', '\x61', '\x62', '\x63', '\x64', '\x65', '\x66', '\x67',
  '\x68', '\x69', '\x6a', '\x6b', '\x6c', '\x6d', '\x6e', '\x6f',
  '\x70', '\x71', '\x72', '\x73', '\x74', '\x75', '\x76', '\x77',
  '\x78', '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e', '\x7f',
  '\xff', '\xad', '\xbd', '\x9c', '\xcf', '\xbe', '\xdd', '\xf5',
  '\xf9', '\xb8', '\xa6', '\xae', '\xaa', '\xf0', '\xa9', '\xee',
  '\xf8', '\xf1', '\xfd', '\xfc', '\xef', '\xe6', '\xf4', '\xfa',
  '\xf7', '\xfb', '\xa7', '\xaf', '\xac', '\xab', '\xf3', '\xa8',
  '\xb7', '\xb5', '\xb6', '\xc7', '\x8e', '\x8f', '\x92', '\x80',
  '\xd4', '\x90', '\xd2', '\xd3', '\xde', '\xd6', '\xd7', '\xd8',
  '\xd1', '\xa5', '\xe3', '\xe0', '\xe2', '\xe5', '\x99', '\x9e',
  '\x9d', '\xeb', '\xe9', '\xea', '\x9a', '\xed', '\xe8', '\xe1',
  '\x85', '\xa0', '\x83', '\xc6', '\x84', '\x86', '\x91', '\x87',
  '\x8a', '\x82', '\x88', '\x89', '\x8d', '\xa1', '\x8c', '\x8b',
  '\xd0', '\xa4', '\x95', '\xa2', '\x93', '\xe4', '\x94', '\xf6',
  '\x9b', '\x97', '\xa3', '\x96', '\x81', '\xec', '\xe7', '\x98',
  '\xd5', '\x9f', '\xf2', '\xc4', '\x00', '\xb3', '\xda', '\x00',
  '\x00', '\x00', '\xbf', '\x00', '\x00', '\x00', '\xc0', '\x00',
  '\x00', '\x00', '\xd9', '\x00', '\x00', '\x00', '\xc3', '\xb4',
  '\xc2', '\xc1', '\xc5', '\xcd', '\xba', '\x00', '\x00', '\xc9',
  '\x00', '\x00', '\xbb', '\x00', '\x00', '\xc8', '\x00', '\x00',
  '\xbc', '\x00', '\x00', '\xcc', '\x00', '\x00', '\xb9', '\x00',
  '\x00', '\xcb', '\x00', '\x00', '\xca', '\x00', '\x00', '\xce',
  '\xdf', '\x00', '\x00', '\x00', '\xdc', '\x00', '\x00', '\x00',
  '\xdb', '\xb0', '\xb1', '\xb2', '\xfe',
};

SMB_GENERATE_CHARSET_MODULE_8_BIT_GAP(CP850)

