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

#ifndef LEXER_HPP
#define LEXER_HPP

#include <string>
#include <fstream>
#include <vector>

struct basic_lexer
{
	enum {
		T_EOF=-1,
		T_MAX_TOKEN = 256
	};

	struct iterator
	{
		struct token
		{
			int type() const { return _type; }
			std::string value() const { return _value; }

			int _type;
			std::string _value;
		};
	
		iterator(basic_lexer *lex);
		iterator() : lex(0) { }
		iterator operator++();
		iterator operator++(int);
		iterator operator--();
		iterator operator--(int);
		token &operator*() { return tok; }
		token *operator->() { return &tok; }

		basic_lexer *lex;
		std::vector<std::string::iterator> la;
		size_t pos;
		token tok;
	};
	
	iterator begin()  { return iterator(this); }
	iterator end() { return iterator(); }

	basic_lexer(std::string input) : data(input) { }
	basic_lexer(std::istream &input) :
		data(std::istreambuf_iterator<char>(input.rdbuf()),
		     std::istreambuf_iterator<char>()) { }
	virtual ~basic_lexer() { }

	std::string::iterator _begin() { return data.begin(); }
	virtual std::string::iterator _next(std::string::iterator, int &);
	std::string::iterator _end() { return data.end(); }

	std::string data;
};

bool operator==(const basic_lexer::iterator &lhs,
		const basic_lexer::iterator &rhs);
bool operator!=(const basic_lexer::iterator &lhs,
		const basic_lexer::iterator &rhs);

#endif
