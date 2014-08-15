/* -------------------------------------------------------------------------- **
 * Microsoft Network Services for Unix, AKA., Andrew Tridgell's SAMBA.
 *
 * This module Copyright (C) 1990-1998 Karl Auer
 *
 * Rewritten almost completely by Christopher R. Hertel
 * at the University of Minnesota, September, 1997.
 * This module Copyright (C) 1997-1998 by the University of Minnesota
 * -------------------------------------------------------------------------- **
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * -------------------------------------------------------------------------- **
 *
 * Module name: params
 *
 * -------------------------------------------------------------------------- **
 *
 *  This module performs lexical analysis and initial parsing of a
 *  Windows-like parameter file.  It recognizes and handles four token
 *  types:  section-name, parameter-name, parameter-value, and
 *  end-of-file.  Comments and line continuation are handled
 *  internally.
 *
 *  The entry point to the module is function pm_process().  This
 *  function opens the source file, calls the Parse() function to parse
 *  the input, and then closes the file when either the EOF is reached
 *  or a fatal error is encountered.
 *
 *  A sample parameter file might look like this:
 *
 *  [section one]
 *  parameter one = value string
 *  parameter two = another value
 *  [section two]
 *  new parameter = some value or t'other
 *
 *  The parameter file is divided into sections by section headers:
 *  section names enclosed in square brackets (eg. [section one]).
 *  Each section contains parameter lines, each of which consist of a
 *  parameter name and value delimited by an equal sign.  Roughly, the
 *  syntax is:
 *
 *    <file>            :==  { <section> } EOF
 *
 *    <section>         :==  <section header> { <parameter line> }
 *
 *    <section header>  :==  '[' NAME ']'
 *
 *    <parameter line>  :==  NAME '=' VALUE '\n'
 *
 *  Blank lines and comment lines are ignored.  Comment lines are lines
 *  beginning with either a semicolon (';') or a pound sign ('#').
 *
 *  All whitespace in section names and parameter names is compressed
 *  to single spaces.  Leading and trailing whitespace is stipped from
 *  both names and values.
 *
 *  Only the first equals sign in a parameter line is significant.
 *  Parameter values may contain equals signs, square brackets and
 *  semicolons.  Internal whitespace is retained in parameter values,
 *  with the exception of the '\r' character, which is stripped for
 *  historic reasons.  Parameter names may not start with a left square
 *  bracket, an equal sign, a pound sign, or a semicolon, because these
 *  are used to identify other tokens.
 *
 * -------------------------------------------------------------------------- **
 */

#include "replace.h"
#include "lib/util/samba_util.h"
#include "tini.h"

bool pm_process(const char *filename,
		bool (*sfunc)(const char *section, void *private_data),
		bool (*pfunc)(const char *name, const char *value,
			      void *private_data),
		void *private_data)
{
	FILE *f;
	bool ret;

	f = fopen(filename, "r");
	if (f == NULL) {
		return false;
	}

	ret = tini_parse(f, sfunc, pfunc, private_data);

	fclose(f);

	return ret;
}
