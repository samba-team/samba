###################################################
# server template function generator
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package IdlTemplate;

use strict;

my($res);

#####################################################################
# produce boilerplate code for a interface
sub Template($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $name = $interface->{NAME};

	$res .= 
"
/* 
   Unix SMB/CIFS implementation.

   endpoint server for the $name pipe

   Copyright (C) YOUR NAME HERE XXXX
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include \"includes.h\"

";

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			my $fname = $d->{NAME};
			$res .=
"
/* 
  $fname 
*/
static NTSTATUS $fname(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
		       struct $fname *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

";
		}
	}

	$res .= 
"
/* include the generated boilerplate */
#include \"librpc/gen_ndr/ndr_$name\_s.c\"
"
}


#####################################################################
# parse a parsed IDL structure back into an IDL file
sub Parse($)
{
	my($idl) = shift;
	$res = "";
	foreach my $x (@{$idl}) {
		($x->{TYPE} eq "INTERFACE") && 
		    Template($x);
	}
	return $res;
}

1;

