###############################################################################
##
##  smb.conf Command Line Editor
##  Copyright (C) Jim McDonough <jmcd@us.ibm.com>    2004.
##   
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 2 of the License, or
##  (at your option) any later version.
##   
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##   
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, write to the Free Software
##  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
##  July 14, 2004 - Anthony Liguori <aliguori@us.ibm.com>
##   o Initial release of code
##
###############################################################################

OBJ=smbconf.o basic_lexer.o main.o
CXXFLAGS=-g -Wall -I.

all: smbconf_edit

smbconf_edit: $(OBJ)
	$(CXX) -o smbconf_edit $(CXXFLAGS) $(LDFLAGS) $(OBJ) $(LIBS)

smbconf_edit.1.gz: smbconf_edit
	help2man ./smbconf_edit | gzip > smbconf_edit.1.gz 

install: smbconf_edit smbconf_edit.1.gz
	install smbconf_edit /usr/local/bin/smbconf_edit
	install smbconf_edit.1.gz /usr/local/man/man1/smbconf_edit.1.gz

clean:
	$(RM) $(OBJ) smbconf_edit
