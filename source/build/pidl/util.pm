###################################################
# utility functions to support pidl
# Copyright tridge@samba.org 2000
# released under the GNU GPL
package util;

use Data::Dumper;

sub dumpit($)
{
	my $a = shift;
	return Dumper $a;
}

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
	    if (ref($v->[$i]) eq "ARRAY" && $#{$v->[$i]}==-1) { delete($v->[$i]); next; }
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
    open(INPUTFILE, $filename) || die "can't load $filename";
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
	return "$1.$ext";
    }
    return "$fname.$ext";
}

#####################################################################
# save a data structure into a file
sub SaveStructure($$)
{
    my($filename) = shift;
    my($v) = shift;
    FileSave($filename, Dumper($v));
}

#####################################################################
# load a data structure from a file (as saved with SaveStructure)
sub LoadStructure($)
{
    return eval FileLoad(shift);
}

#####################################################################
# see if a pidl property list contains a give property
sub has_property($$)
{
	my($props) = shift;
	my($p) = shift;
	
	foreach my $d (@{$props}) {
		if (ref($d) ne "HASH") {
			if ($d eq $p) {
				return 1;
			}
		} else {
			foreach my $k (keys %{$d}) {
				if ($k eq $p) {
					return $d->{$k};
				}
			}
		}
	}

    return undef;
}


sub is_scalar_type($)
{
    my($type) = shift;

    return 1, if ($type eq "uint32");
    return 1, if ($type eq "long");
    return 1, if ($type eq "short");
    return 1, if ($type eq "char");
    return 1, if ($type eq "uint8");
    return 1, if ($type eq "uint16");
    return 1, if ($type eq "hyper");
    return 1, if ($type eq "wchar_t");

    return 0;
}

sub is_builtin_type($)
{
    my($type) = shift;

    return 1, if (is_scalar_type($type));
    return 1, if ($type =~ "unistr.*");
    return 1, if ($type eq "security_descriptor");
    return 1, if ($type eq "dom_sid");
    return 1, if ($type eq "dom_sid2");
    return 1, if ($type eq "policy_handle");

    return 0;
}


1;

