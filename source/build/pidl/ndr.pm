###################################################
# Samba4 NDR info tree generator
# Copyright tridge@samba.org 2000-2003
# Copyright tpot@samba.org 2001
# Copyright jelmer@samba.org 2004-2005
# released under the GNU GPL

package Ndr;

use strict;

#####################################################################
# return a table describing the order in which the parts of an element
# should be parsed
sub GetElementLevelTable($)
{
	my $e = shift;

	return ($e->{NDR_ORDER_TABLE}) if (defined $e->{NDR_ORDER_TABLE});

	my $order = [];
	my $is_deferred = 0;
	
	# First, all the pointers
	foreach my $i (1..need_wire_pointer($e)) {
		push (@$order, { 
			TYPE => "POINTER",
			# for now, there can only be one pointer type per element
			POINTER_TYPE => pointer_type($e),
			IS_DEFERRED => "$is_deferred"
		});
		# everything that follows will be deferred
		$is_deferred = 1;
	}

	if (defined($e->{ARRAY_LEN})) {
		push (@$order, {
			TYPE => "ARRAY",
			ARRAY_TYPE => array_type($e),
			SIZE_IS => util::has_property($e, "size_is"),
			LENGTH_IS => util::has_property($e, "length_is"),
			IS_DEFERRED => "$is_deferred"
		});
	}

	if (my $sub_size = util::has_property($e, "subcontext")) {
		push (@$order, {
			TYPE => "SUBCONTEXT",
			SUBCONTEXT_SIZE => $sub_size,
			IS_DEFERRED => $is_deferred
		});
	}

	if (my $switch = util::has_property($e, "switch_is")) {
		push (@$order, {
			TYPE => "SWITCH", 
			SWITCH_IS => $switch,
			IS_DEFERRED => $is_deferred
		});
	}

	push (@$order, {
		TYPE => "DATA",
		NAME => $e->{NAME},
		IS_DEFERRED => $is_deferred,
		CONTAINS_DEFERRED => can_contain_deferred($e)
	});

	$e->{NDR_ORDER_TABLE} = $order;

	return $order;
}

#####################################################################
# see if a type contains any deferred data 
sub can_contain_deferred
{
	my $e = shift;

	return 1 if ($e->{POINTERS});
	return 0 if (is_scalar_type($e->{TYPE}));
	return 0 if (util::has_property($e, "subcontext"));
	return 1 unless (typelist::hasType($e->{TYPE})); # assume the worst

	my $type = typelist::getType($e->{TYPE});

	foreach my $x (@{$type->{DATA}->{ELEMENTS}}) {
		return 1 if (can_contain_deferred ($x));
	}
	
	return 0;
}

sub is_scalar_type($)
{
    my $type = shift;

	return 0 unless typelist::hasType($type);

	if (my $dt = typelist::getType($type)->{DATA}->{TYPE}) {
		return 1 if ($dt eq "SCALAR" or $dt eq "ENUM" or $dt eq "BITMAP");
	}

    return 0;
}

sub pointer_type($)
{
	my $e = shift;

	return undef unless $e->{POINTERS};
	
	return "ref" if (util::has_property($e, "ref"));
	return "ptr" if (util::has_property($e, "ptr"));
	return "unique" if (util::has_property($e, "unique"));
	return "relative" if (util::has_property($e, "relative"));
	return "ignore" if (util::has_property($e, "ignore"));

	return undef;
}

# return 1 if this is a fixed array
sub is_fixed_array($)
{
	my $e = shift;
	my $len = $e->{"ARRAY_LEN"};
	return 1 if (defined $len && util::is_constant($len));
	return 0;
}

# return 1 if this is a conformant array
sub is_conformant_array($)
{
	my $e = shift;
	return 1 if (util::has_property($e, "size_is"));
	return 0;
}

# return 1 if this is a inline array
sub is_inline_array($)
{
	my $e = shift;
	my $len = $e->{"ARRAY_LEN"};
	if (is_fixed_array($e) ||
	    defined $len && $len ne "*") {
		return 1;
	}
	return 0;
}

# return 1 if this is a varying array
sub is_varying_array($)
{
	my $e = shift;
	return util::has_property($e, "length_is");
}

# return 1 if this is a surrounding array (sometimes 
# referred to as an embedded array). Can only occur as 
# the last element in a struct and can not contain any pointers.
sub is_surrounding_array($)
{
	my $e = shift;

	return ($e->{POINTERS} == 0 
		and defined $e->{ARRAY_LEN} 
		and	$e->{ARRAY_LEN} eq "*"
		and $e == $e->{PARENT}->{ELEMENTS}[-1] 
		and $e->{PARENT}->{TYPE} ne "FUNCTION");
}

sub array_type($)
{
	my $e = shift;

	return "conformant-varying" if (is_varying_array($e) and is_conformant_array($e));
	return "conformant" if (is_varying_array($e));
	return "varying" if (is_varying_array($e));
	return "inline" if (is_inline_array($e));
	return "fixed" if (is_fixed_array($e));

	return undef;
}

# determine if an element needs a reference pointer on the wire
# in its NDR representation
sub need_wire_pointer($)
{
	my $e = shift;

	my $n = $e->{POINTERS};
	my $pt = pointer_type($e);

	# Top level "ref" pointers do not have a referrent identifier
	if (	defined($pt) 
		and $pt eq "ref" 
		and $e->{PARENT}->{TYPE} eq "FUNCTION") 
	{
		$n--;
	}

	return $n;
}

1;
