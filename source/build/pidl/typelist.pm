###################################################
# Samba4 parser generator for IDL structures
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package typelist;

use strict;

my %typedefs;

sub addType($)
{
	my $t = shift;
	$typedefs{$t->{NAME}} = $t;
}

sub getType($)
{
	my $t = shift;
	return undef unless(defined($typedefs{$t}));
	return $typedefs{$t};
}

sub hasType($)
{
	my $t = shift;
	return 1 if defined($typedefs{$t});
	return 0;
}

sub RegisterPrimitives()
{
	my @primitives = (
		"char", "int8", "uint8", "short", "wchar_t", 
		"int16", "uint16", "long", "int32", "uint32", 
		"dlong", "udlong", "udlongr", "NTTIME", "NTTIME_1sec", 
		"time_t", "DATA_BLOB", "error_status_t", "WERROR", 
		"NTSTATUS", "boolean32", "unsigned32", "ipv4address", 
		"hyper", "NTTIME_hyper");
		
	foreach my $k (@primitives) {
		$typedefs{$k} = {
			NAME => $k,
			TYPE => "TYPEDEF",
			DATA => {
				TYPE => "SCALAR",
				NAME => $k
			}
		};
	}
}

RegisterPrimitives();

1;
