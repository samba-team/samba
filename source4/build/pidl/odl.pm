##########################################
# Converts ODL stuctures to IDL structures
# (C) 2004-2005 Jelmer Vernooij <jelmer@samba.org>

package ODL;

use strict;

sub FunctionAddObjArgs($)
{
	my $e = shift;
	
	unshift(@{$e->{ELEMENTS}}, {
		'NAME' => 'ORPCthis',
		'POINTERS' => 0,
		'PROPERTIES' => { 'in' => '1' },
		'TYPE' => 'ORPCTHIS'
	});
	unshift(@{$e->{ELEMENTS}}, {
		'NAME' => 'ORPCthat',
		'POINTERS' => 0,
		'PROPERTIES' => { 'out' => '1' },
		'TYPE' => 'ORPCTHAT'
	});
}

sub ReplaceInterfacePointers($)
{
	my $e = shift;

	foreach my $x (@{$e->{ELEMENTS}}) {
		next unless typelist::hasType($x);
		next unless typelist::getType($x)->{DATA}->{TYPE} eq "INTERFACE";
		
		$x->{TYPE} = "MInterfacePointer";
	}
}

# Add ORPC specific bits to an interface.
sub ODL2IDL($)
{
	my $odl = shift;
	my @idl = @{$odl};
	
	foreach my $x (@idl) {
		# Add [in] ORPCTHIS *this, [out] ORPCTHAT *that
		# for 'object' interfaces
		if (util::has_property($x, "object")) {
			foreach my $e (@{$x->{DATA}}) {
				($e->{TYPE} eq "FUNCTION") && FunctionAddObjArgs($e);
				ReplaceInterfacePointers($e);
			}
		}
	}

	return \@idl;
}

1;
