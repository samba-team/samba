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

#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>
#include <getopt.h>

#include "smbconf.hpp"

static void print_usage(const char *name)
{
  std::cout
    << "Usage: " << name << " [OPTIONS] SMBCONF" << std::endl
    << "Modifies SMBCONF adding, removing, or modifying options." << std::endl
    << std::endl
    << "  -d, --delete=SECTION[/ATTR] deletes a section or attribute"
    << std::endl
    << "  -s, --set=SECTION/ATTR=VAL  set an option" << std::endl
    << "  -g, --get=SECTION/ATTR      get an option" << std::endl
    << "  -v, --verbose               output verbose (human readable) output"
    << std::endl
    << "  -V, --version               output version information and exit" 
    << std::endl
    << "  -h, --help                  display this help and exit" << std::endl
    << std::endl
    << "Make sure to specify the SECTION even for attributes in the global "
    << "section." << std::endl
    << std::endl
    << "Report bugs to <aliguori@us.ibm.com>." << std::endl;
}

static bool split_argument(char *argument,
			   char **section,
			   char **attribute,
			   char **value = 0)
{
  bool ret = true;

  *section = argument;
  if ((*attribute = strchr(argument, '/'))) {
    **attribute = 0;
    (*attribute)++;
  } else {
    ret = false;
  }

  if (ret && value) {
    if ((*value = strchr(*attribute, '='))) {
      char *ptr = *value;

      while (isspace(*--ptr)) {
	*ptr = 0;
      }

      **value = 0;
      ptr = *value;

      while (isspace(*++ptr)) {
	*ptr = 0;
      }

      *value = ptr;
    } else {
      ret = false;
    }
  } else if (ret && strchr(*attribute, '=')) {
    ret = false;
  }

  return ret;
}

struct SetItem
{
  SetItem() { }
  SetItem(std::string section, std::string attribute, std::string value) :
    section(section), attribute(attribute), value(value) { }

  std::string section;
  std::string attribute;
  std::string value;
};

struct GetItem
{
  GetItem() { }
  GetItem(std::string section, std::string attribute) :
    section(section), attribute(attribute) { }

  std::string section;
  std::string attribute;
};

int main(int argc, char **argv)
{
  struct option long_opts[] = {
    { "delete",  1, 0, 'd' },
    { "set",     1, 0, 's' },
    { "get",     1, 0, 'g' },
    { "verbose", 0, 0, 'v' },
    { "version", 0, 0, 'V' },
    { "help",    0, 0, 'h' },
    { 0,         0, 0, 0   }
  };
  const char *short_opts = "d:s:g:vVh";
  int opt_ind = 0;
  char ch;
  char *section;
  char *attribute;
  char *value = 0;
  std::vector<SetItem> set_items;
  std::vector<GetItem> get_items;
  std::vector<GetItem> delete_items;
  bool verbose = false;

  while ((ch=getopt_long(argc, argv, short_opts, long_opts, &opt_ind)) != -1) {
    switch (ch) {
    case 's':
      if (!split_argument(optarg, &section, &attribute, &value)) {
	print_usage(*argv);
	exit(1);
      }
      set_items.push_back(SetItem(section, attribute, value));
      break;
    case 'g':
      if (!split_argument(optarg, &section, &attribute)) {
	print_usage(*argv);
	exit(1);
      }
      get_items.push_back(GetItem(section, attribute));
      break;
    case 'd':
      split_argument(optarg, &section, &attribute);

      if (attribute == 0) {
	delete_items.push_back(GetItem(section, ""));
      } else {
	delete_items.push_back(GetItem(section, attribute));
      }
      break;
    case 'v':
      verbose = true;
      break;
    case 'V':
      std::cout << "smbconf v0.1" << std::endl
		<< "Copyright (C) Jim McDonough <jmcd@us.ibm.com>    2004." << std::endl
		<< "Written by Anthony Liguori <aliguori@us.ibm.com>"
		<< std::endl;
      exit(1);
      break;
    case 'h':
      print_usage(*argv);
      exit(0);
      break;
    default:
      break;
    }
  }

  if ((argc - optind) != 1) {
    print_usage(*argv);
    exit(1);
  }

  std::ifstream smb_conf_stream(argv[optind]);
  if (!smb_conf_stream.is_open()) {
    std::cerr << "Could not open file `" << argv[optind]
	      << "' for reading." << std::endl;
    exit(1);
  }
  smbconf_lexer smb_conf_lexer(smb_conf_stream);
  smbconf_t smb_conf;

  smb_conf_lexer.begin() >> smb_conf;
  smb_conf_stream.close();

  for (size_t i = 0; i < get_items.size(); i++) {
    if (verbose) {
      std::cout << get_items[i].section << "/" << get_items[i].attribute 
		<< " = ";
    }

    std::cout << smb_conf[get_items[i].section][get_items[i].attribute] 
	      << std::endl;
  }

  for (size_t i = 0; i < set_items.size(); i++) {
    smb_conf[set_items[i].section][set_items[i].attribute] =
      set_items[i].value;
  }

  for (size_t i = 0; i < delete_items.size(); i++) {
    if (delete_items[i].attribute == "") {
      smb_conf[delete_items[i].section].deleted = true;
    } else {
      smb_conf[delete_items[i].section].
	attrs[delete_items[i].attribute].deleted = true;
    }
  }

  if (!set_items.empty() || !delete_items.empty()) {
    std::ofstream smb_conf_stream(argv[optind]);

    if (!smb_conf_stream.is_open()) {
      std::cerr << "Could not open file `" << argv[optind]
		<< "' for writing." << std::endl;
      exit(1);
    }

    smb_conf_stream << smb_conf;
  }
}
