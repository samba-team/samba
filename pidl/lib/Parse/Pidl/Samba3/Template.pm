###################################################
# server template function generator
# Copyright tridge@samba.org 2003
# released under the GNU GPL

package Parse::Pidl::Samba3::Template;

use vars qw($VERSION);
$VERSION = '0.01';

use Parse::Pidl::Util qw(genpad);

use strict;
use warnings;

my($res);

#####################################################################
# produce boilerplate code for a interface
sub Template($)
{
	my($interface) = shift;
	my($data) = $interface->{DATA};
	my $name = $interface->{NAME};

	$res .=
"/*
   Unix SMB/CIFS implementation.

   endpoint server for the $name pipe

   Copyright (C) YOUR NAME HERE YEAR

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include \"includes.h\"
#include \"ntdomain.h\"
#include \"../librpc/gen_ndr/srv_$name.h\"

";

	foreach my $d (@{$data}) {
		if ($d->{TYPE} eq "FUNCTION") {
			my $fname = $d->{NAME};
			my $pad = genpad("$d->{RETURN_TYPE} _$fname");
			$res .=
"
/****************************************************************
 _$fname
****************************************************************/

$d->{RETURN_TYPE} _$fname(struct pipes_struct *p,
$pad"."struct $fname *r)
{
";

	$res .= "\tp->fault_state = DCERPC_FAULT_OP_RNG_ERROR;\n";
	if ($d->{RETURN_TYPE} eq "NTSTATUS") {
		$res .= "\treturn NT_STATUS_NOT_IMPLEMENTED;\n";
	} elsif ($d->{RETURN_TYPE} eq "WERROR") {
		$res .= "\treturn WERR_NOT_SUPPORTED;\n";
	} elsif ($d->{RETURN_TYPE} eq "HRESULT") {
		$res .= "\treturn HRES_ERROR_NOT_SUPPORTED;\n";
	}

	$res .= "}

";
		}
	}
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
