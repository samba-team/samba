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

#include "smbconf.hpp"

std::string &section_t::operator[](std::string name)
{
  attribute_t attr;

  if (!attrs.count(name)) {
    token_t eol;
    eol._type = smbconf_lexer::T_EOL;
    eol._value = "\n";
    attr.top_comments.push_back(eol);

    if (attrs.size()) {
      std::vector<token_t>::iterator i =
	attrs.begin()->second.top_comments.end();
      --i;
      if (i->type() == smbconf_lexer::T_WHITESPACE) {
	attr.top_comments.push_back(*i);
      }
    } else {
      token_t ws;
      ws._type = smbconf_lexer::T_WHITESPACE;
      ws._value = "\t";
      attr.top_comments.push_back(ws);
    }

    attr.name = name;
    attr.order = attrs.size();
    attrs[name] = attr;
  }

  return attrs[name].value;
}

section_t &smbconf_t::operator[](std::string name)
{
  if (!sects.count(name)) {
    section_t sect;

    if (!sects.empty()) {
      token_t eol;
      eol._type = smbconf_lexer::T_EOL;
      eol._value = "\n";
      sect.comments.push_back(eol);
      sect.comments.push_back(eol);
    }
    sect.name = name;
    sect.order = sects.size();
    return (sects[name] = sect);
  }

  return sects[name];
}

iterator operator>>(iterator lhs, whitespace_t &ws)
{
  iterator ret = lhs;

  ws.resize(0);

  while (ret->type() == smbconf_lexer::T_WHITESPACE ||
	 ret->type() == smbconf_lexer::T_EOL ||
	 ret->type() == smbconf_lexer::T_COMMENT) {
    ws.push_back(*ret);
    ++ret;
  }

  return ret;
}

iterator operator>>(iterator lhs, attribute_t &attr)
{
  iterator ret = lhs >> attr.top_comments;

  if (ret->type() != smbconf_lexer::T_WORD) {
    return lhs;
  }

  while (ret->type() == smbconf_lexer::T_WORD) {
    if (!attr.name.empty()) attr.name += " ";
    attr.name += ret->value();
    ++ret;
    while (ret->type() == smbconf_lexer::T_WHITESPACE) ++ret;
  }

  if (ret->type() == '=') {
    ++ret;
    while (ret->type() == smbconf_lexer::T_WHITESPACE) ++ret;

    while (ret->type() != smbconf_lexer::T_EOF &&
	   ret->type() != smbconf_lexer::T_EOL &&
	   ret->type() != smbconf_lexer::T_COMMENT) {
      attr.value += ret->value();
      ++ret;
    }
  }

  attr.side_comments.resize(0);
  if (ret->type() == smbconf_lexer::T_COMMENT) {
    attr.side_comments.push_back(*ret);
    ++ret;
  }
  return ret;
}

iterator operator>>(iterator lhs, section_t &sect)
{
  iterator ret = lhs >> sect.comments;

  if (ret->type() == '[') {
    ++ret;
    bool first = true;

    sect.name = "";

    do {
      while (ret->type() == smbconf_lexer::T_WHITESPACE) ++ret;

      if (ret->type() == smbconf_lexer::T_WORD) {
	if (!first) {
	  sect.name += " ";
	} else {
	  first = false;
	}
	sect.name += ret->value();
	++ret;
      } else {
	break;
      }
    } while (ret->type() != ']');

    if (ret->type() == ']') {
      ++ret;
    } else {
      ret = lhs;
    }
  } else {
    ret = lhs;
  }

  iterator tmp;

  std::map<std::string, attribute_t>().swap(sect.attrs);

  do {
    attribute_t attr;
    tmp = ret;
    ret = ret >> attr;
    attr.order = sect.attrs.size();
    if (tmp != ret && !attr.name.empty()) sect.attrs[attr.name] = attr;
  } while (tmp != ret);

  return ret;
}

iterator operator>>(iterator lhs, smbconf_t &smbconf)
{
  section_t sect;
  iterator i;
  int count = 0;

  do {
    i = lhs;
    lhs = lhs >> sect;
    if (lhs != i) {
      sect.order = count++;
      smbconf.sects[sect.name] = sect;
    }
  } while (lhs != i);

  lhs = lhs >> smbconf.bottom_comments;

  return lhs;
}

std::ostream &operator<<(std::ostream &lhs, const whitespace_t &ws)
{
  whitespace_t::const_iterator i;

  for (i = ws.begin(); i != ws.end(); ++i) {
    lhs << i->value();
  }

  return lhs;
}

std::ostream &operator<<(std::ostream &lhs, const attribute_t &attr)
{
  if (attr.deleted) return lhs;

  lhs << attr.top_comments;
  lhs << attr.name;
  if (!attr.value.empty()) {
    lhs << " =" << (!isspace(attr.value[0]) ? " " : "") << attr.value;
  }
  lhs << attr.side_comments;

  return lhs;
}

std::ostream &operator<<(std::ostream &lhs, const section_t &sect)
{
  if (sect.deleted) return lhs;

  std::vector<const attribute_t *> attrs;
  std::map<std::string, attribute_t>::const_iterator i;

  attrs.resize(sect.attrs.size());

  lhs << sect.comments;
  lhs << "[" << sect.name << "]";

  for (i = sect.attrs.begin(); i != sect.attrs.end(); ++i) {
    attrs[i->second.order] = &i->second;
  }

  for (size_t j = 0; j < attrs.size(); ++j) {
    lhs << *attrs[j];
  }

  return lhs;
}

std::ostream &operator<<(std::ostream &lhs, const smbconf_t &smbconf)
{
  std::map<std::string, section_t>::const_iterator i;
  std::vector<const section_t *> sects;

  sects.resize(smbconf.sects.size());

  for (i = smbconf.sects.begin(); i != smbconf.sects.end(); ++i) {
    sects[i->second.order] = &i->second;
  }

  for (size_t j = 0; j < sects.size(); ++j) {
    lhs << *sects[j];
  }

  lhs << smbconf.bottom_comments;

  return lhs;
}
