/*\
 *  smb.conf Command Line Editor
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>    2004.
 *   
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *   
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *   
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  July 14, 2004 - Anthony Liguori <aliguori@us.ibm.com>
 *   o Initial release of code
 *
\*/

#ifndef SMBCONF_LEXER_HPP
#define SMBCONF_LEXER_HPP

#include "basic_lexer.hpp"

struct smbconf_lexer : basic_lexer
{
	enum {
		T_WHITESPACE = basic_lexer::T_MAX_TOKEN,
		T_COMMENT,
		T_STRING,
		T_WORD,
		T_EOL,
		T_MAX_TOKEN
	};

	smbconf_lexer(std::ifstream &input) : basic_lexer(input) { }
	smbconf_lexer(std::string &input) : basic_lexer(input) { } 

protected:
	std::string::iterator _next(std::string::iterator _pos, int &type) {
		std::string::iterator pos = _pos;

		if (*pos == '\n') {
			type = T_EOL;
			++pos;
		} else if (isspace(*pos)) {
			type = T_WHITESPACE;
			++pos;
			while (*pos != '\n' && isspace(*pos)) ++pos;
		} else if (*pos == '#' || *pos == ';') {
			type = T_COMMENT;
			++pos;
			while (pos != data.end() && *pos != '\n') ++pos;
		} else if (*pos == '\"') {
			type = T_STRING;
			++pos;
			while (pos != data.end() && *pos != '\n' &&
			       *pos != '\"') {
				if (*pos == '\\') ++pos;
				if (pos != data.end()) ++pos;
			}

			if (*pos == '\n') {
				pos = _pos;
				type = *pos;
				++pos;
			}
		} else if (*pos == '=' || *pos == '[' || *pos == ']' ||
			   *pos == '\\') {
			type = *pos;
			++pos;
		} else if (isalnum(*pos) || ispunct(*pos)) {
			type = T_WORD;
			++pos;
			while (isalnum(*pos) || (ispunct(*pos) &&
						 *pos != '=' && *pos != '[' &&
						 *pos != ']' && *pos != '\\'))
				++pos;
		} else {
			pos = basic_lexer::_next(pos, type);
		}

		return pos;
	}
};

#endif
