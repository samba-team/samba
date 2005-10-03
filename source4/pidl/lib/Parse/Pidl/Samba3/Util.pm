###################################################
# Samba3 common helper functions
# Copyright jelmer@samba.org 2005
# released under the GNU GPL

package Parse::Pidl::Samba3::Util;

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(MapSamba3Type);

use strict;
use Parse::Pidl::Typelist qw(hasType getType mapType);
use Parse::Pidl::Util qw(has_property ParseExpr);
use Parse::Pidl::NDR qw(GetPrevLevel GetNextLevel ContainsDeferred);

use vars qw($VERSION);
$VERSION = '0.01';

sub MapSamba3Type($)
{
	my $e = shift;
	
	return "UNISTR2 $e->{NAME}"  if ($e->{TYPE} eq "string");

	return "$e->{TYPE} $e->{NAME}";
}

1;
