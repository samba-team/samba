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

#ifndef SMBCONF_HPP
#define SMBCONF_HPP

#include <iostream>
#include <vector>
#include <string>
#include <map>

#include "smbconf_lexer.hpp"

typedef smbconf_lexer::iterator iterator;
typedef iterator::token token_t;
typedef std::vector<token_t> whitespace_t;

struct attribute_t
{
  attribute_t() : deleted(false) { }
  whitespace_t top_comments;
  std::string name;
  std::string value;
  whitespace_t side_comments;
  int order;
  bool deleted;
};

struct section_t
{
  section_t() : deleted(false) { }
  whitespace_t comments;
  std::string name;
  std::map<std::string, attribute_t> attrs;
  int order;
  bool deleted;

  std::string &operator[](std::string name);
};

struct smbconf_t
{
  std::map<std::string, section_t> sects;
  whitespace_t bottom_comments;
  section_t &operator[](std::string name);
};

iterator operator>>(iterator lhs, smbconf_t &smbconf);
std::ostream &operator<<(std::ostream &lhs, const smbconf_t &smbconf);

#endif
