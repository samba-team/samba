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

#include "basic_lexer.hpp"

#include <string>
#include <iostream>
#include <fstream>

basic_lexer::iterator::iterator(basic_lexer *lex) :
	lex(lex), pos(1)
{
	la.push_back(lex->_begin());
	la.push_back(lex->_next(la.back(), tok._type));
	tok._value = std::string(la[pos - 1], la[pos]);
}

bool operator==(const basic_lexer::iterator &lhs,
		const basic_lexer::iterator &rhs) {
	return  ((rhs.tok.value().empty() && lhs.tok.value().empty()) ||
		 (rhs.lex == lhs.lex && rhs.pos == lhs.pos));
}

bool operator!=(const basic_lexer::iterator &lhs,
		const basic_lexer::iterator &rhs) {
	return !(lhs == rhs);
}

basic_lexer::iterator basic_lexer::iterator::operator++() {
	if (++pos == la.size()) {
		la.push_back(lex->_next(la.back(), tok._type));
		tok._value = std::string(la[pos - 1], la[pos]);
	} else {
		lex->_next(la[pos - 1], tok._type);
		tok._value = std::string(la[pos - 1], la[pos]);
	}

	return *this;
}

basic_lexer::iterator basic_lexer::iterator::operator++(int) {
	iterator copy(*this);

	if (++pos == la.size()) {
		la.push_back(lex->_next(la.back(), tok._type));
		tok._value = std::string(la[pos - 1], la[pos]);
	} else {
		lex->_next(la[pos - 1], tok._type);
		tok._value = std::string(la[pos - 1], la[pos]);
	}

	return copy;
}

basic_lexer::iterator basic_lexer::iterator::operator--() {
	if (pos != 1) --pos;
	lex->_next(la[pos - 1], tok._type);
	tok._value = std::string(la[pos - 1], la[pos]);
	return *this;
}

basic_lexer::iterator basic_lexer::iterator::operator--(int) {
	iterator copy(*this);

	if (pos != 1) --pos;
	lex->_next(la[pos - 1], tok._type);
	tok._value = std::string(la[pos - 1], la[pos]);
	return copy;
}

std::string::iterator basic_lexer::_next(std::string::iterator pos, int &type)
{
	if (pos == data.end()) {
		type = T_EOF;
		return pos;
	}

	++pos;
	type = *pos;

	return pos;
}
