/*
 * tdbexport.c
 * Copyright (C) 2000 Peter Samuelson <peter@cadcamlab.org>
 *
 * Some bits stolen from tdbtool.c by Andrew Tridgell
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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "tdb.h"

#define MODE_LITERAL	1
#define MODE_HEX	2
#define MODE_BASE64	3
#define MODE_QPRINT	4

#define MODE_ESC_COLON	8 /* flag, so use distinct bit */


const static char *progname = "tdbexport";
static int verbose;
static int line_max = 76; /* for hex and quoted-printable displays */
static int line_len;
static int print_mode = MODE_QPRINT;
static FILE *outfp;

static void do_header(FILE *out, char *filename, int mode)
{
  char *fmt;
  time_t t = time(0);

  switch (mode) {
  case MODE_LITERAL:	return;
  case MODE_HEX:	fmt = "Hex-Dump"; break;
  case MODE_BASE64:	fmt = "Base64"; break;
  case MODE_QPRINT:	fmt = "Quoted-Printable"; break;
  }

  fprintf(out,
	  "; TDB dump file - import with `tdbimport'\n"
	  "; Source: %s\n"
	  "; Date: %s"		/* ctime adds \n */
	  "; Format: %s\n\n",
	  filename, ctime(&t), fmt);
}

static void do_output(FILE *out, unsigned char *buf, int len, int mode)
{
  int i, esc_colon;

  esc_colon = mode & MODE_ESC_COLON;
  mode &= ~MODE_ESC_COLON;

  switch (mode) {

  case MODE_LITERAL:	/* literal characters */
    fwrite(buf, len, 1, out);
    break;

  case MODE_HEX:	/* hexadecimal */
    for (i=0; i<len; i++) {
      int ch=buf[i];
      fprintf(out, "%02X", ch);
      line_len += 2;
      if(line_len >= line_max-1) {
	fputs("\n  ", out);
	line_len = 2;
      }
    }
    break;

  /*
   * MIME Base64 output
   * Believed to be basically RFC1341-compliant.
   * Should be (had better be!) endian-independent.
   */
  case MODE_BASE64:
    for (i=0; i<len; i+=3) {
      static char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      unsigned char ch[4], j;
      char *fmt;

      ch[0] = buf[i];
      ch[1] = i+1 < len ? buf[i+1] : 0;
      ch[2] = i+2 < len ? buf[i+2] : 0;

      ch[3] = base64[ 0x3f & ch[2] ];
      ch[2] = base64[ 0x3f & ((ch[1] << 2) | (ch[2] >> 6)) ];
      ch[1] = base64[ 0x3f & ((ch[0] << 4) | (ch[1] >> 4)) ];
      ch[0] = base64[ ch[0] >> 2 ];

      if (i+2 >= len)
	ch[3] = '=';
      if (i+1 == len)
	ch[2] = '=';

      switch (line_max - line_len) {
      case -1:
      case 0: fmt = "\n  %c%c%c%c"; line_len=6; break;
      case 1: fmt = "%c\n  %c%c%c"; line_len=5; break;
      case 2: fmt = "%c%c\n  %c%c"; line_len=4; break;
      case 3: fmt = "%c%c%c\n  %c"; line_len=3; break;
      default: fmt = "%c%c%c%c";    line_len+=4; break;
      }

      fprintf(out, fmt, ch[0], ch[1], ch[2], ch[3]);
    }
    break;


  /*
   * MIME Quoted-Printable output
   * Believed to be RFC1341-compliant.
   * Also believed to be lossless for any data,
   * which of course is the whole point.
   */
  case MODE_QPRINT:	/* quoted-printable */
    for (i=0; i<len; i++) {
      int ch = buf[i];
      static char tmpbuf[8];
      char *fmt;

      if (ch == '\n') {
	if (i == len-1)	/* final char is newline */
	  fmt = "=0A";
	else
	  fmt = "=0A=\r\n";
      }
      else if ((ch == ' ' && i == len-1) ||	/* space at end of output */
	       (ch == ':' && esc_colon) ||	/* colon in first field */
						/* line starting with ; or # */
	       ((ch == '#' || ch == ';') && esc_colon && line_len == 0) ||
	       (ch == '=' || ch < 32 || ch > 127)) /* non-printable character */
	fmt = "=%02X";
      else
	fmt = "%c";

      line_len += sprintf(tmpbuf, fmt, ch);
      if(line_len >= line_max) {
	fputs("=\r\n", out);
	line_len = strlen(tmpbuf);
      }
      fputs(tmpbuf, out);

    }
    break;
  default:
    fprintf(stderr, "%s: unknown output mode %d\n", progname, mode);
    exit(1);
  }
}

/* callback for db traversal */
int export_cb(TDB_CONTEXT *unused1, TDB_DATA key, TDB_DATA dbuf, void *unused2)
{
  do_output(outfp, key.dptr, key.dsize, print_mode | MODE_ESC_COLON);
  fputc(':', outfp); line_len++;
  do_output(outfp, dbuf.dptr, dbuf.dsize, print_mode);
  fputc('\n', outfp); line_len = 0;

  /*  free(key.dptr);	// README is wrong */
  /*  free(dbuf.dptr);	// README is wrong */
  return 0;
}

static void usage(void)
{
  fprintf(stderr,
	  "usage: %s [-x|-p|-l] [-m N] [-o output] dbfile\n"
	  "  -x    output in a hexadecimal format\n"
	  "  -b    output in MIME Base64 format\n"
	  "  -p    output in MIME Quoted-Printable format\n"
	  "  -l    output literal characters (warning: can be lossy!)\n"
	  "  -o    name of output file\n"
          "  -m    maximum number of characters per output line\n"
          "        (ignored in \"literal\" mode)\n"
	  "The database file is not optional.\n"
	  "Default output mode is Quoted-Printable.\n", progname);
  exit(1);
}

int main(int argc, char *argv[])
{
  char *dbfile;
  int o;
  char *outfile = NULL;
  TDB_CONTEXT *t;

  while((o=getopt(argc, argv, "h?-blpxo:m:")) != -1) {
    switch(o) {
    case 'h': case '?': case '-': usage(); break;

    case 'b': print_mode = MODE_BASE64; break;
    case 'l': print_mode = MODE_LITERAL; break;
    case 'p': print_mode = MODE_QPRINT; break;
    case 'x': print_mode = MODE_HEX; break;

    case 'o': outfile = optarg; break;

    case 'm':
      if(!sscanf(optarg, "%i", &line_max))
	usage();
      break;
    }
  }
  dbfile = argv[optind];
  if(!dbfile)
    usage();

  if(outfile) {
    outfp = fopen(outfile, "w");
    if(!outfp) {
      perror(progname);
      exit(1);
    }
  } else {
    outfp = stdout;
  }
  
  t = tdb_open(dbfile, 0, 0, O_RDONLY, 0);
  if(!t) {
    /*    fprintf(stderr, "%s: %s\n", progname, tdb_error(t)); */
    /* oops, that doesn't make much sense, does it? tdb_error(NULL)? */
    fprintf(stderr, "%s: cannot open TDB file %s\n", progname, dbfile);
    exit(1);
  }

  do_header(outfp, dbfile, print_mode);

  tdb_traverse(t, export_cb, 0);

  tdb_close(t);
  return 0;
}
