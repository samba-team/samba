###################################################
# utility functions to support pidl
# Copyright tridge@samba.org 2000
# released under the GNU GPL
package util;

#####################################################################
# load a data structure from a file (as saved with SaveStructure)
sub LoadStructure($)
{
	my $f = shift;
	my $contents = FileLoad($f);
	defined $contents || return undef;
	return eval "$contents";
}

use strict;

#####################################################################
# flatten an array of arrays into a single array
sub FlattenArray2($) 
{ 
    my $a = shift;
    my @b;
    for my $d (@{$a}) {
	for my $d1 (@{$d}) {
	    push(@b, $d1);
	}
    }
    return \@b;
}

#####################################################################
# flatten an array of arrays into a single array
sub FlattenArray($) 
{ 
    my $a = shift;
    my @b;
    for my $d (@{$a}) {
	for my $d1 (@{$d}) {
	    push(@b, $d1);
	}
    }
    return \@b;
}

#####################################################################
# flatten an array of hashes into a single hash
sub FlattenHash($) 
{ 
    my $a = shift;
    my %b;
    for my $d (@{$a}) {
	for my $k (keys %{$d}) {
	    $b{$k} = $d->{$k};
	}
    }
    return \%b;
}


#####################################################################
# traverse a perl data structure removing any empty arrays or
# hashes and any hash elements that map to undef
sub CleanData($)
{
    sub CleanData($);
    my($v) = shift;
    if (ref($v) eq "ARRAY") {
	foreach my $i (0 .. $#{$v}) {
	    CleanData($v->[$i]);
	    if (ref($v->[$i]) eq "ARRAY" && $#{$v->[$i]}==-1) { 
		    $v->[$i] = undef; 
		    next; 
	    }
	}
	# this removes any undefined elements from the array
	@{$v} = grep { defined $_ } @{$v};
    } elsif (ref($v) eq "HASH") {
	foreach my $x (keys %{$v}) {
	    CleanData($v->{$x});
	    if (!defined $v->{$x}) { delete($v->{$x}); next; }
	    if (ref($v->{$x}) eq "ARRAY" && $#{$v->{$x}}==-1) { delete($v->{$x}); next; }
	}
    }
}


#####################################################################
# return the modification time of a file
sub FileModtime($)
{
    my($filename) = shift;
    return (stat($filename))[9];
}


#####################################################################
# read a file into a string
sub FileLoad($)
{
    my($filename) = shift;
    local(*INPUTFILE);
    open(INPUTFILE, $filename) || return undef;
    my($saved_delim) = $/;
    undef $/;
    my($data) = <INPUTFILE>;
    close(INPUTFILE);
    $/ = $saved_delim;
    return $data;
}

#####################################################################
# write a string into a file
sub FileSave($$)
{
    my($filename) = shift;
    my($v) = shift;
    local(*FILE);
    open(FILE, ">$filename") || die "can't open $filename";    
    print FILE $v;
    close(FILE);
}

#####################################################################
# return a filename with a changed extension
sub ChangeExtension($$)
{
    my($fname) = shift;
    my($ext) = shift;
    if ($fname =~ /^(.*)\.(.*?)$/) {
	return "$1$ext";
    }
    return "$fname$ext";
}

#####################################################################
# a dumper wrapper to prevent dependence on the Data::Dumper module
# unless we actually need it
sub MyDumper($)
{
	require Data::Dumper;
	my $s = shift;
	return Data::Dumper::Dumper($s);
}

#####################################################################
# save a data structure into a file
sub SaveStructure($$)
{
	my($filename) = shift;
	my($v) = shift;
	FileSave($filename, MyDumper($v));
}

#####################################################################
# find an interface in an array of interfaces
sub get_interface($$)
{
	my($if) = shift;
	my($n) = shift;

	foreach(@{$if}) {
		if($_->{NAME} eq $n) { return $_; }
	}
	
	return 0;
}

#####################################################################
# see if a pidl property list contains a given property
sub has_property($$)
{
	my($e) = shift;
	my($p) = shift;

	if (!defined $e->{PROPERTIES}) {
		return undef;
	}

	return $e->{PROPERTIES}->{$p};
}

#####################################################################
# see if a pidl property matches a value
sub property_matches($$$)
{
	my($e) = shift;
	my($p) = shift;
	my($v) = shift;

	if (!defined has_property($e, $p)) {
		return undef;
	}

	if ($e->{PROPERTIES}->{$p} =~ /$v/) {
		return 1;
	}

	return undef;
}

# determine if an element is a pass-by-reference structure
sub is_ref_struct($)
{
	my $e = shift;
	if (!is_scalar_type($e->{TYPE}) &&
	    has_property($e, "ref")) {
		return 1;
	}
	return 0;
}

# determine the array size (size_is() or ARRAY_LEN)
sub array_size($)
{
	my $e = shift;
	my $size = has_property($e, "size_is");
	if ($size) {
		return $size;
	}
	$size = $e->{ARRAY_LEN};
	if ($size) {
		return $size;
	}
	return undef;
}

# return 1 if the string is a C constant
sub is_constant($)
{
	my $s = shift;
	if (defined $s && $s =~ /^\d/) {
		return 1;
	}
	return 0;
}

# return a "" quoted string, unless already quoted
sub make_str($)
{
	my $str = shift;
	if (substr($str, 0, 1) eq "\"") {
		return $str;
	}
	return "\"" . $str . "\"";
}

###################################
# find a sibling var in a structure
sub find_sibling($$)
{
	my($e) = shift;
	my($name) = shift;
	my($fn) = $e->{PARENT};

	if ($name =~ /\*(.*)/) {
		$name = $1;
	}

	for my $e2 (@{$fn->{ELEMENTS}}) {
		return $e2 if ($e2->{NAME} eq $name);
	}

	return undef;
}

1;
