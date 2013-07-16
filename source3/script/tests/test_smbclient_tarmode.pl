#!/usr/bin/perl

# Unix SMB/CIFS implementation.
# Test suite for the tar backup mode of smbclient.
# Copyright (C) Aurélien Aptel 2013

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

=head1 NAME

C<test_smbclient_tarmode.pl> - Test for smbclient tar backup feature

=cut

# flags to test

# c        DONE
# c g      DONE
# c a      DONE
# c N      DONE
# c I      DONE
# c I r    DONE
# c X      DONE
# c X r    DONE
# c F      DONE
# c F r    DONE
# x        DONE
# x I      DONE
# x I r    #
# x X      DONE
# x X r    #
# x F      DONE
# x F r    DONE

use v5.14;
use strict;
use warnings;

use Archive::Tar;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use File::Path qw/make_path remove_tree/;
use File::Temp;
use Getopt::Long;
use Pod::Usage;
use Term::ANSIColor;

sub d {print Dumper @_;}

# DEFAULTS
# 'our' to make them available in the File package
our $USER      = '';
our $PW        = '';
our $HOST      = 'localhost';
our $IP        = '';
our $SHARE     = 'public';
our $DIR       = 'tar_test_dir';
our $LOCALPATH = '/media/data/smb-test';
our $TMP       = File::Temp->newdir();
our $BIN       = 'smbclient';

my $SELECTED_TEST = '';
my $LIST_TEST = 0;

my @SMBARGS   = ();

our $DEBUG = 0;
my $MAN   = 0;
my $HELP  = 0;
my $CLEAN = 0;

# all tests
my @TESTS = (
    ['create, normal files (no attributes)',        \&test_creation_normal,      'normal'],
    ['create, normal nested files (no attributes)', \&test_creation_normal,      'nested'],
    ['create, incremental with -g',                 \&test_creation_incremental, '-g'],
    ['create, incremental with tarmode',            \&test_creation_incremental, 'tarmode inc'],
    ['create, reset archived files with -a',        \&test_creation_reset,       '-a'],
    ['create, reset archived files with tarmode',   \&test_creation_reset,       'tarmode reset'],
    ['create, files newer than a file',             \&test_creation_newer],
    ['create, combination of tarmode filter',       \&test_creation_attr],
    ['create, explicit include',                    \&test_creation_include],
#    ['create, explicit exclude',                    \&test_creation_exclude],
    ['create, include w/ filelist (F)',             \&test_creation_list],
#   ['create, wildcard and regex',                  \&test_creation_wildcard],
    ['extract, normal files',                       \&test_extraction_normal],
    ['extract, explicit include',                   \&test_extraction_include],
    ['extract, explicit exclude',                   \&test_extraction_exclude],
    ['extract, include w/ filelist (F)',            \&test_extraction_list],
#   ['extract, wildcard and regex',                 \&test_extraction_wildcard],
);

=head1 SYNOPSIS

 test_smbclient_tarmode.pl [options] -- [smbclient options]

 Options:
    -h, --help    brief help message
    --man         full documentation

  Environment:
    -u, --user      USER
    -p, --password  PW
    -h, --host      HOST
    -i, --ip        IP
    -s, --share     SHARE
    -d, --dir       PATH
        sub-path to use on the share

    -l, --local-path  PATH
        path to the root of the samba share on the machine.

    -b, --bin  BIN
        path to the smbclient binary to use

  Test:
    --list
       list tests

    --test N
    --test A-B
    --test A,B,D-F

       only run certain tests (accept list and intervals of numbers)

=cut

GetOptions('u|user=s'       => \$USER,
           'p|password=s'   => \$PW,
           'h|host=s'       => \$HOST,
           'i|ip=s'         => \$IP,
           's|share=s'      => \$SHARE,
           'd|dir=s'        => \$DIR,
           'l|local-path=s' => \$LOCALPATH,
           'b|bin=s'        => \$BIN,

           'test=s'         => \$SELECTED_TEST,
           'list'           => \$LIST_TEST,

           'clean'          => \$CLEAN,
           'debug'          => \$DEBUG,
           'h|help'         => \$HELP,
           'man'            => \$MAN) or pod2usage(2);

pod2usage(0) if $HELP;
pod2usage(-exitval => 0, -verbose => 2) if $MAN;
list_test(), exit 0 if $LIST_TEST;

if ($USER xor $PW) {
    die "Need both user and password when one is provided\n";
}
elsif ($USER and $PW) {
    push @SMBARGS, '-U'.$USER.'%'.$PW;
}
else {
    push @SMBARGS, '-N';
}

if ($IP) {
    push @SMBARGS, '-I', $IP;
}

# remaining arguments are passed to smbclient
push @SMBARGS, @ARGV;

# path to store the downloaded tarball
my $TAR = "$TMP/tarmode.tar";

#####

# SANITIZATION

# remove all final slashes from input paths
$LOCALPATH =~ s{[/\\]+$}{}g;
$SHARE =~ s{[/\\]+$}{}g;
$HOST =~ s{[/\\]+$}{}g;
$DIR =~ s{[/\\]+$}{}g;

if (!-d $LOCALPATH) {
    die "Local path '$LOCALPATH' is not a directory.\n";
}

if ($CLEAN) {
    # clean the whole root first
    remove_tree($LOCALPATH, { keep_root => 1 });
}

#####

# RUN TESTS

my @selection = parse_test_string($SELECTED_TEST);

if ($SELECTED_TEST eq '') {
    run_test(@TESTS);
} elsif (@selection > 0) {
    run_test(@selection);
} else {
    die "Test selection '$SELECTED_TEST' is invalid\n";
}

#################################

=head1 DOCUMENTATION

=head2 Defining a test

=over

=item * Create a function C<test_yourtest>

=item * Use the File module, documented below

=item * Use C<smb_tar>, C<smb_client>, C<check_tar> or C<check_remote>

=item * Return number of error

=item * Add function to C<@TESTS>

=back

The function must be placed in the C<@TESTS> list along with a short
description and optional arguments.

=cut

sub test_creation_newer {
    my @files;
    my $dt = 3000;

    # create oldest file at - DT
    my $oldest = File->new_remote('oldest');
    $oldest->set_time(time - $dt);

    # create limit file
    my $limit = File->new_local("$TMP/limit");

    # create newA file at + DT
    my $newA = File->new_remote('newA');
    $newA->set_time(time + $dt);

    # create newB file at + DT
    my $newB = File->new_remote('newB');
    $newB->set_time(time + $dt);

    # get files newer than limit_file
    push @files, $newA, $newB;

    smb_tar('', '-TcN', $limit->localpath, $TAR, $DIR);
    return check_tar($TAR, \@files);
}

sub test_creation_attr {
    my @attr = qw/r h s a/;
    my @all;
    my @inc;
    my $err = 0;

    # one normal file
    my $f = File->new_remote("file-n.txt");
    push @all, $f;

    # combinations of attributes
    for my $n (1..@attr) {
        for (combine(\@attr, $n)) {
            my @t = @$_;
            my $fn = "file-" . join('+', @t) . ".txt";
            my $f = File->new_remote($fn);
            $f->set_attr(@t);
            push @all, $f;
        }
    }

    @inc = grep { !$_->attr('s') } @all;
    smb_tar('tarmode nosystem', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    @inc = grep { !$_->attr('h') } @all;
    smb_tar('tarmode nohidden', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    @inc = grep { !$_->attr_any('h', 's') } @all;
    smb_tar('tarmode nohidden nosystem', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    @inc = grep { $_->attr('a') && !$_->attr_any('h', 's') } @all;
    smb_tar('tarmode inc nohidden nosystem', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    $err;
}

sub test_creation_reset {
    my ($mode) = @_;

    my @files;
    my $n = 3;
    for (1..$n) {
        my $f = File->new_remote("file-$_");
        $f->set_attr('a');
        push @files, $f;
    }

    if ($mode =~ /reset/) {
        smb_tar('tarmode full reset', '-Tc', $TAR, $DIR);
    } else {
        smb_tar('', '-Tca', $TAR, $DIR);
    }

    my $err = check_tar($TAR, \@files);
    return $err if ($err > 0);

    for my $f (File::list($DIR)) {
        if ($f->{attr}{a}) {
            printf " ! %s %s\n", $f->attr_str, $f->remotepath;
            $err++;
        }
    }
    return $err;
}

sub test_creation_normal {
    my ($mode) = @_;

    my $prefix = ($mode =~ /nest/) ? "/foo/bar/bar/" : '';
    my @files;
    my $n = 5;
    for (1..$n) {
        my $f = File->new_remote($prefix."file-$_");
        push @files, $f;
    }
    smb_tar('tarmode full', '-Tc', $TAR, $DIR);
    return check_tar($TAR, \@files);
}

sub test_creation_incremental {
    my ($mode) = @_;

    my @files;
    my $n = 10;
    for (1..$n) {
        my $f = File->new_remote("file-$_");

        # set archive bit on ~half of them
        if ($_ < $n/2) {
            $f->set_attr('a');
            push @files, $f;
        }
        else {
            $f->set_attr((qw/n r s h/)[$_ % 4]);
        }
    }

    if ($mode =~ /inc/) {
        smb_tar('tarmode inc', '-Tc', $TAR, $DIR);
    } else {
        smb_tar('', '-Tcg', $TAR, $DIR);
    }
    return check_tar($TAR, \@files);
}


sub test_extraction_normal {
    my @files;
    my $n = 5;
    for (1..$n) {
        my $f = File->new_remote("file-$_");
        push @files, $f;
    }

    # store
    smb_tar('', '-Tc', $TAR, $DIR);
    my $err = check_tar($TAR, \@files);
    return $err if $err > 0;

    reset_remote();

    smb_tar('', '-Tx', $TAR);
    check_remote($DIR, \@files);
}

sub test_extraction_include {
    my @all_files;
    my @inc_files;

    for (qw(file_inc inc/b inc/c inc/dir/foo dir_ex/d zob)) {
        my $f = File->new_remote($_);
        push @all_files, $f;
        push @inc_files, $f if /inc/;
    }

    # store
    smb_tar('', '-Tc', $TAR, $DIR);
    my $err = check_tar($TAR, \@all_files);
    return $err if $err > 0;

    reset_remote();

    smb_tar('', '-TxI', $TAR, "$DIR/file_inc", "$DIR/inc");
    check_remote($DIR, \@inc_files);
}

sub test_extraction_exclude {
    my @all_files;
    my @inc_files;

    for (qw(file_exc exc/b exc/c exc/dir/foo dir_ex/d zob)) {
        my $f = File->new_remote($_);
        push @all_files, $f;
        push @inc_files, $f if !/exc/;
    }

    # store
    smb_tar('', '-Tc', $TAR, $DIR);
    my $err = check_tar($TAR, \@all_files);
    return $err if $err > 0;

    reset_remote();

    smb_tar('', '-TxX', $TAR, "$DIR/file_exc", "$DIR/exc");
    check_remote($DIR, \@inc_files);
}


sub test_creation_include {
    my @files;

    for (qw(file_inc inc/b inc/c inc/dir/foo dir_ex/d zob)) {
        my $f = File->new_remote($_);
        push @files, $f if /inc/;
    }

    smb_tar('', '-TcI', $TAR, "$DIR/file_inc", "$DIR/inc");
    return check_tar($TAR, \@files);
}

sub test_creation_exclude {
    my @files;

    for (qw(file_ex ex/b ex/c ex/dir/foo foo/bar zob)) {
        my $f = File->new_remote($_);
        push @files, $f if !/ex/;
    }

    smb_tar('', '-TcX', $TAR, "$DIR/file_ex", "$DIR/ex");
    return check_tar($TAR, \@files);
}

sub test_creation_list {
    my @inc_files;

    for (qw(file_inc inc/b inc/c inc/dir/foo foo/bar zob)) {
        my $f = File->new_remote($_);
        push @inc_files, $f if /inc/;
    }

    my $flist = File->new_local("$TMP/list", file_list(@inc_files));
    smb_tar('', '-TcF', $TAR, $flist->localpath);
    return check_tar($TAR, \@inc_files);
}

sub test_creation_wildcard {
    my @exts = qw(txt jpg exe);
    my @dirs = ('', "$DIR/", "$DIR/dir/");
    my @all;
    my $nb;
    my $err = 0;

    $nb = 0;
    for my $dir (@dirs) {
        for (@exts) {
            my $fn = $dir . "file$nb." . $_;
            my $f = File->new_remote($fn, 'ABSPATH');
            $f->delete_on_destruction(1);
            push @all, $f;
            $nb++;
        }
    }

    $nb = 0;
    for my $dir (@dirs) {
        for my $ext (@exts) {
            my @inc;

            my $fn = $dir."file$nb.".$ext;
            my $pattern = $dir.'*.'.$ext;
            my $flist;

            # include

            @inc = grep { $_->remotepath eq $fn } @all;
            smb_tar('', '-Tc', $TAR, $pattern);
            $err += check_tar($TAR, \@inc);

            # include with -r

            # supposed to be the same results but if you include a
            # pattern not at the root -> tar will be empty... bug?
            @inc = grep { $_->remotepath eq $fn } @all;
            smb_tar('', '-Tcr', $TAR, $pattern);
            $err += check_tar($TAR, \@inc);

            # exclude with -r

            # supposed to work on the whole hierarchy
            @inc = grep { my $n = $_->remotepath; $n !~ /$ext/} @all;
            smb_tar('', '-TcrX', $TAR, "*.$ext");
            $err += check_tar($TAR, \@inc);

            # # exclude
            # @inc = grep { my $n = $_->remotepath; $n !~ /$ext/ && $n !~ /dir/} @all;
            # smb_tar('', '-TcX', $TAR, "$DIR/*.$ext");
            # #$err += check_tar($TAR, \@inc);
            # $err += check_tar($TAR, \@all);

            # with F

            $flist = File->new_local("$TMP/list", "$pattern\n");

            # include with F r

            @inc = grep { $_->remotepath eq $fn } @all;
            smb_tar('', '-TcFr', $TAR, $flist->localpath);
            $err += check_tar($TAR, \@inc);
        }
    }

    $err;
}

sub test_extraction_wildcard {
    my @exts = qw(txt jpg exe);
    my @dirs = ('', "$DIR/", "$DIR/dir/");
    my $nb;
    my $err = 0;

    for my $dir (@dirs) {

        my @all;

        $nb = 0;
        for my $dir (@dirs) {
            for (@exts) {
                my $fn = $dir . "file$nb." . $_;
                my $f = File->new_remote($fn, 'ABSPATH');
                $f->delete_on_destruction(1);
                push @all, $f;
                $nb++;
            }
        }


        my @inc;
        my $ext = 'exe';
        my $fn = $dir."file$nb.".$ext;
        my $pattern = $dir.'*.'.$ext;
        my $flist;

        # with F

        $flist = File->new_local("$TMP/list", "$pattern\n");

        # store
        my $re = '^'.$dir.'.*file';
        @inc = grep { $dir eq '' or $_->remotepath =~ m{$re} } @all;
        smb_tar('', '-Tc', $TAR, $dir);
        $err += check_tar($TAR, \@inc);

        reset_remote();
        my $re2 = '^'.$dir.'file.+exe';
        @inc = grep { $_->remotepath =~ /$re2/ } @all;
        smb_tar('', '-TxrF', $TAR, $flist->localpath);
        $err += check_remote($dir, \@inc);

        reset_remote();
    }

    $err;
}

sub test_extraction_list {
    my @inc_files;
    my @all_files;

    for (qw(file_inc inc/b inc/c inc/dir/foo foo/bar zob)) {
        my $f = File->new_remote($_);
        push @all_files, $f;
        push @inc_files, $f if /inc/;
    }

    # store
    smb_tar('', '-Tc', $TAR, $DIR);
    my $err = check_tar($TAR, \@all_files);
    return $err if $err > 0;

    reset_remote();

    my $flist = File->new_local("$TMP/list", file_list(@inc_files));
    smb_tar('', '-TxF', $TAR, $flist->localpath);
    return check_remote($DIR, \@inc_files);
}

#################################

# IMPLEMENTATION

=head2 Useful functions

Here are a list of useful functions and helpers to define tests.

=cut

# list test number and description
sub list_test {
    my $i = 0;
    for (@TESTS) {
        my ($desc, $f, @args) = @$_;
        printf "%2d.\t%s\n", $i++, $desc;
    }
}

sub run_test {
    for (@_) {
        my ($desc, $f, @args) = @$_;
        reset_env();
        say "TEST: $desc";
        my $err = $f->(@args);
        print_res($err);
        print "\n";
    }
    reset_env();
}

sub parse_test_string {
    my $s = shift;
    my @tests = ();

    if (!length($s)) {
        return ();
    }

    for (split /,/, $s) {
        when (/^\d+$/) {
            if ($_ >= @TESTS) {
                return ();
            }
            push @tests, $TESTS[$_];
        }
        when (/^(\d+)-(\d+)$/) {
            my ($min, $max) = sort ($1, $2);
            if ($max >= @TESTS) {
                return ();
            }

            for ($min..$max) {
                push @tests, $TESTS[$_];
            }
        }
        default {
            return ();
        }
    }

    return @tests;
}

sub print_res {
    my $err = shift;
    if ($err) {
        printf " RES: %s%d ERR%s\n", color('bold red'), $err, color 'reset';
    } else {
        printf " RES: %sOK%s\n", color('bold green'), color 'reset';
    }
}

=head3 C<combine ( \@set, $n )>

=head3 C<combine ( ['a', 'b', 'c'], 2 )>

Return a list of all possible I<n>-uplet (or combination of C<$n> element) of C<@set>.

=cut
sub combine {
    my ($list, $n) = @_;
    die "Insufficient list members" if $n > @$list;

    return map [$_], @$list if $n <= 1;

    my @comb;

    for (my $i = 0; $i+$n <= @$list; $i++) {
        my $val = $list->[$i];
        my @rest = @$list[$i+1..$#$list];
        push @comb, [$val, @$_] for combine(\@rest, $n-1);
    }

    return @comb;
}


=head3 C<reset_remote( )>

Remove all files in the server C<$DIR> (not root)

=cut
sub reset_remote {
    remove_tree($LOCALPATH . '/'. $DIR);
    make_path($LOCALPATH . '/'. $DIR);
}

=head3 C<reset_tmp( )>

Remove all files in the temp directory C<$TMP>

=cut
sub reset_tmp {
    remove_tree($TMP, { keep_root => 1 });
}


=head3 C<reset_env( )>

Remove both temp and remote (C<$DIR>) files

=cut
sub reset_env {
    reset_tmp();
    reset_remote();
}

=head3 C<file_list ( @files )>

Make a multiline string of all the files remote path, one path per line.

C<@files> must be a list of C<File> instance.

=cut
sub file_list {
    my @files = @_;
    my $s = '';
    for (@files) {
        $s .= $_->remotepath."\n";
    }
    return $s;
}

=head3 C<check_remote( $remotepath, \@files )>

Check if C<$remotepath> has B<exactly> all the C<@files>.

Print a summary on STDOUT.

C<@files> must be a list of C<File> instance.

=cut
sub check_remote {
    my ($subpath, $files) = @_;
    my (%done, %expected);
    my (@less, @more, @diff);

    for (@$files) {
        $expected{$_->remotepath} = $_;
        $done{$_->remotepath} = 0;
    }

    my %remote;
    File::walk(sub { $remote{$_->remotepath} = $_ }, File::tree($subpath));

    for my $rfile (keys %remote) {

        # files that shouldn't be there
        if (!exists $expected{$rfile}) {
            say " +    $rfile";
            push @more, $rfile;
            next;
        }

        # same file multiple times
        if ($done{$rfile} > 0) {
            $done{$rfile}++;
            push @more, $rfile;
            printf " +%3d %s\n", $done{$rfile}, $rfile;
            next;
        }

        $done{$rfile}++;

        # different file
        my $rmd5 = $remote{$rfile}->md5;
        if ($expected{$rfile}->md5 ne $rmd5) {
            say " !    $rfile ($rmd5)";
            push @diff, $rfile;
            next;
        }

        if ($DEBUG) {
            say "      $rfile";
        }
    }

    # file that should have been in tar
    @less = grep { $done{$_} == 0 } keys %done;
    for (@less) {
        say " -    $_";
    }

    # summary
    printf("\t%d files, +%d, -%d, !%d\n",
           scalar keys %done,
           scalar @more,
           scalar @less,
           scalar @diff);
    return (@more + @less + @diff); # nb of errors
}

=head3 C<check_tar( $path_to_tar, \@files )>

Check if the archive C<$path_to_tar> has B<exactly> all the C<@files>.

Print a summary on C<STDOUT>;

C<@files> must be a list of C<File> instance.

=cut
sub check_tar {
    my ($tar, $files) = @_;
    my %done;
    my (@less, @more, @diff);

    my %h;

    for (@$files) {
        $h{$_->tarpath} = $_;
        $done{$_->tarpath} = 0;
    }

    my $total = 0;
    my $i = Archive::Tar->iter($tar, 1, {md5 => 1});
    while (my $f = $i->()) {
        if ($f->has_content) {
            $total++;
            my $p = $f->full_path;

            # file that shouldn't be there
            if (!exists $done{$p}) {
                push @more, $p;
                say " +    $p";
                next;
            }

            # same file multiple times
            if ($done{$p} > 0) {
                $done{$p}++;
                push @more, $p;
                printf " +%3d %s\n", $done{$p}, $p;
                next;
            }

            $done{$p}++;

            # different file

            my $md5 = $f->data;
            if ($^V lt v5.16) {
                $md5 = md5_hex($md5);
            }

            if ($md5 ne $h{$p}->md5) {
                say " !    $p ($md5)";
                push @diff, $p;
                next;
            }

            if ($DEBUG) {
                say "      $p";
            }
        }
    }

    # file that should have been in tar
    @less = grep { $done{$_} == 0 } keys %done;
    for (@less) {
        say " -    $_";
    }

    # summary
    printf("\t%d files, +%d, -%d, !%d\n",
           $total,
           scalar @more,
           scalar @less,
           scalar @diff);
    return (@more + @less + @diff); # nb of errors
}

=head3 C<smb_client ( @args )>

Run smbclient with C<@args> passed as argument and return output.

Each element of C<@args> becomes one escaped argument of smbclient.

Host, share, user, password and the additionnal arguments provided on
the command-line are already inserted.

The output contains both the C<STDOUT> and C<STDERR>.

Die if smbclient crashes or exits with an error code.

=cut
sub smb_client {
    my (@args) = @_;

    my $fullpath = "//$HOST/$SHARE";
    my $cmd = sprintf("%s %s %s",
                      quotemeta($BIN),
                      quotemeta($fullpath),
                      join(' ', map {quotemeta} (@SMBARGS, @args)));

    if ($DEBUG) {
        say color('bold yellow'),$cmd =~ s{\\([./+-])}{$1}gr,color('reset');
    }

    my $out = `$cmd 2>&1`;
    my $err = $?;
    # handle abnormal exit
    if ($err == -1) {
        print STDERR "failed to execute $cmd: $!\n";
    }
    elsif ($err & 127) {
        printf STDERR  "child died with signal %d (%s)\n", ($err & 127), $cmd;
    }
    elsif ($err >> 8) {
        printf STDERR "child exited with value %d (%s)\n", ($err >> 8), $cmd;
    }

    if ($DEBUG) {
        say $out;
    }

    if ($err) {
        say "ERROR";
        say $out;
        exit 1;
    }
    return $out;
}

sub smb_cmd {
    return smb_client('-c', join(' ', @_));
}

=head3 C<smb_tar( $cmd, @args )>

=head3 C<smb_tar( 'tarmode inc', '-Tc', $TAR, $DIR )>

Run C<$cmd> command and use C<@args> as argument and return output.

Wrapper around C<smb_client> for tar calls.

=cut
sub smb_tar {
    my ($cmd, @rest) = @_;
    printf " CMD: %s\n ARG: %s\n", $cmd, join(' ', @rest);
    smb_client((length($cmd) ? ('-c', $cmd) : ()), @rest);
}

=head3 C<random( $min, $max )>

Return integer in C<[ $min ; $max ]>

=cut
sub random {
    my ($min, $max) = @_;
    ($min, $max) = ($max, $min) if ($min > $max);
    $min + int(rand($max - $min));
}

#################################

package File;

=head2 The File module

All the test should use the C<File> class. It has nice functions and
methods to deal with paths, to create random files, to list the
content of the server, to change attributes, etc.

There are 2 kinds of C<File>: remote and local.

=over

=item * Remote files are accessible on the server.

=item * Local files are not.

=back

Thus, some methods only works on remote files. If they do not make
sense for local ones, they always return undef.

=cut
use File::Basename;
use File::Path qw/make_path remove_tree/;
use Digest::MD5 qw/md5_hex/;
use Scalar::Util 'blessed';

=head3 Constructors

=head4 C<< File->new_remote($path [, $abs]) >>

Creates a file accessible on the server at C<$DIR/$path> ie. not at the
root of the share.

If you want to remove the automatic prefix C<$DIR>, set C<$abs> to 1.

The file is created without any DOS attributes.

If C<$path> contains non-existent directories, they are automatically
created.

=cut
sub new_remote {
    my ($class, $path, $abs) = @_;
    my ($file, $dir) = fileparse($path);

    $dir = '' if $dir eq './';
    my $loc;

    if ($abs) {
        $loc = cleanpath($main::LOCALPATH.'/'.$dir);
    } else {
        $dir = cleanpath($main::DIR.'/'.$dir);
        $loc = cleanpath($main::LOCALPATH.'/'.$dir);
    }

    make_path($loc);

    my $self = bless {
        'attr' => {qw/r 0 s 0 h 0 a 0 d 0 n 0/},
        'dir'  => $dir,
        'name' => $file,
        'md5'  => create_file($loc.'/'.$file),
        'remote' => 1,
    }, $class;

    $self->set_attr();

    $self;
}

=head4 C<< File->new_local($abs_path [, $data]) >>

Creates a file at C<$abs_path> with $data in it on the system.
If $data is not provided, fill it with random bytes.

=cut
sub new_local {
    my ($class, $path, $data) = @_;
    my ($file, $dir) = fileparse($path);

    make_path($dir);

    my $md5;

    if (defined $data) {
        open my $f, '>', $path or die "can't write in $path: $!";
        print $f $data;
        close $f;
        $md5 = md5_hex($data);
    } else {
        $md5 = create_file($path);
    }

    my $self = {
        'attr' => {qw/r 0 s 0 h 0 a 0 d 0 n 0/},
        'dir'  => $dir,
        'name' => $file,
        'md5'  => $md5,
        'remote' => 0,
    };

    bless $self, $class;
}

=head3 Methods

=head4 C<< $f->localpath >>

Return path on the system eg. F</opt/samba/share/test_tar_mode/file>

=cut
sub localpath {
    my $s = shift;
    if ($s->{remote}) {
        return cleanpath($main::LOCALPATH.'/'.$s->remotepath);
    }
    else {
        return cleanpath($s->{dir}.'/'.$s->{name});
    }
}

=head4 C<< $f->remotepath >>

Return path on the server share.

Return C<undef> if the file is local.

=cut
sub remotepath {
    my ($s) = @_;
    return undef if !$s->{remote};
    cleanpath(($s->{dir}.'/'.$s->{name}) =~ s{^/}{}r);
}


=head4 C<< $f->remotedir >>

Return the directory path of the file on the server.

Like C<< $f->remotepath >> but without the final file name.

=cut
sub remotedir {
    my $s = shift;
    return undef if !$s->{remote};
    cleanpath($s->{dir});
}

=head4 C<< $f->tarpath >>

Return path as it would appear in a tar archive.

Like C<< $f->remotepath >> but prefixed with F<./>

=cut
sub tarpath {
    my $s = shift;
    return undef if !$s->{remote};
    cleanpath('./'.$s->remotepath);
}

=head4 C<< $f->delete_on_destruction( 0 ) >>

=head4 C<< $f->delete_on_destruction( 1 ) >>

By default, a C<File> is not deleted on the filesystem when it is not
referenced anymore in Perl memory.

When set to 1, the destructor unlink the file if it is not already removed.
If the C<File> created directories when constructed, it does not remove them.

=cut
sub delete_on_destruction {
    my ($s, $delete) = @_;
    $s->{delete_on_destruction} = $delete;
}

=head4 C<< $f->set_attr( ) >>

=head4 C<< $f->set_attr( 'a' ) >>

=head4 C<< $f->set_attr( 'a', 'r', 's', 'h' ) >>

Remove all DOS attributes and only set the one provided.

=cut
sub set_attr {
    my ($s, @flags) = @_;
    return undef if !$s->{remote};

    $s->{attr} = {qw/r 0 s 0 h 0 a 0 d 0 n 0/};

    for (@flags) {
        $s->{attr}{lc($_)} = 1;
    }

    my $file = $s->{name};
    my @args;
    if ($s->remotedir) {
        push @args, '-D', $s->remotedir;
    }
    main::smb_client(@args, '-c', qq{setmode "$file" -rsha});
    if (@flags && $flags[0] !~ /n/i) {
        main::smb_client(@args, '-c', qq{setmode "$file" +}.join('', @flags));
    }
}

=head4 C<< $f->attr_any( 'a' ) >>

=head4 C<< $f->attr_any( 'a', 's', ... ) >>

Return 1 if the file has any of the DOS attributes provided.

=cut
sub attr_any {
    my ($s, @flags) = @_;
    for (@flags) {
        return 1 if $s->{attr}{$_};
    }
    0;
}


=head4 C<< $f->attr( 'a' ) >>

=head4 C<< $f->attr( 'a', 's', ... ) >>

Return 1 if the file has all the DOS attributes provided.

=cut
sub attr {
    my ($s, @flags) = @_;
    for (@flags) {
        return 0 if !$s->{attr}{$_};
    }
    1;
}

=head4 C<< $f->attr_str >>

Return DOS attributes as a compact string.

  Read-only, hiden, system, archive => "rhsa"

=cut
sub attr_str {
    my $s = shift;
    return undef if !$s->{remote};
    join('', map {$_ if $s->{attr}{$_}} qw/r h s a d n/);
}

=head4 C<< $f->set_time($t) >>

Set modification and access time of the file to C<$t>.

C<$t> must be in Epoch time (number of seconds since 1970/1/1).

=cut
sub set_time {
    my ($s, $t) = @_;
    utime $t, $t, $s->localpath;
}

=head4 C<< $f->md5 >>

Return md5 sum of the file.

The result is cached.

=cut
sub md5 {
    my $s = shift;

    if (!$s->{md5}) {
        open my $h, '<', $s->localpath() or die "can't read ".$s->localpath.": $!";
        binmode $h;
        $s->{md5} = Digest::MD5->new->addfile($h)->hexdigest;
        close $h;
    }

    return $s->{md5};
}

sub DESTROY {
    my $s = shift;
    if ($s->{delete_on_destruction} && -f $s->localpath) {
        if ($main::DEBUG) {
            say "DESTROY ".$s->localpath;
        }
        unlink $s->localpath;
    }
}

=head3 Functions

=head4 C<< File::walk( \&function, @files) >>

=head4 C<< File::walk( sub { ... }, @files) >>

Iterate on file hierachy in C<@files> and return accumulated results.

Use C<$_> in the sub to access the current C<File>.

The C<@files> must come from a call to the C<File::tree> function.

=cut
sub walk {
    my $fun = \&{shift @_};

    my @res;

    for (@_) {
        if ($_->{attr}{d}) {
            push @res, walk($fun, @{$_->{content}});
        } else {
            push @res, $fun->($_);
        }
    }

    return @res;
}

=head4 C<< File::list( $remotepath ) >>

Return list of file (C<File> instance) in C<$remotepath>.

C<$remotepath> must be a directory.

=cut
sub list {
    my ($path) = @_;
    $path ||= '/';
    my @files;
    my $out = main::smb_client('-D', $path, '-c', 'ls');

    for (split /\n/, $out) {
        next if !/^  (.+?)\s+([AHSRDN]*)\s+(\d+)\s+(.+)/o;
        my ($fn, $attr, $size, $date) = ($1, $2, $3, $4);
        next if $fn =~ /^\.{1,2}$/;

        push @files, bless {
            'remote' => 1,
            'dir'    => $path =~ s{^/}{}r,
            'name'   => $fn,
            'size'   => int($size),
            'date'   => $date,
            'attr'   => {
                # list context returns something different than the
                # boolean matching result => force scalar context
                'a' => scalar ($attr =~ /A/),
                'h' => scalar ($attr =~ /H/),
                's' => scalar ($attr =~ /S/),
                'r' => scalar ($attr =~ /R/),
                'd' => scalar ($attr =~ /D/),
                'n' => scalar ($attr =~ /N/),
            },
        }, 'File';
    }
    return @files;
}

=head4 C<< File::tree( $remotepath ) >>

Return recursive list of file in C<$remotepath>.

C<$remotepath> must be a directory.

Use C<File::walk()> to iterate over all the files.

=cut
sub tree {
    my ($d) = @_;
    my @files;

    if (!defined $d) {
        @files = list();
    } elsif (blessed $d) {
        @files = list($d->remotepath);
    } else {
        @files = list($d);
    }

    for my $f (@files) {
        if ($f->{attr}{d}) {
            $f->{content} = [tree($f)];
        }
    }

    return @files;
}

# remove trailing or duplicated slash
sub cleanpath {
    my $p = shift;
    $p =~ s{/+}{/}g;
    $p =~ s{/$}{};
    $p;
}

# create random file at path local path $fn
sub create_file {
    my $fn = shift;
    my $buf = '';
    unlink $fn if -e $fn;
    my $size = main::random(512, 1024);
    open my $out, '>', $fn or die "can't open $fn: $!\n";
    binmode $out;
    for (1..$size) {
        $buf .= pack('C', main::random(0, 256));
    }
    print $out $buf;
    close $out;
    return md5_hex($buf);
}


=head3 Examples

    # create remote file in $DIR/foo/bar
        my $f = File->new_remote("foo/bar/myfile");
        say $f->localpath;  # /opt/share/$DIR/foo/bar/myfile
        say $f->remotepath; # $DIR/foo/bar/myfile
        say $f->remotedir;  # $DIR/foo/bar


    # same but in root dir
        my $f = File->new_remote("myfile", 1);
        say $f->localpath;  # /opt/share/myfile
        say $f->remotepath; # myfile
        say $f->remotedir;  #


    # create local random temp file in $TMP
        my $f = File->new_local("$TMP/temp");
        say $f->remotepath; # undef because it's not on the server


    # same but file contains "hello"
        my $f = File->new_local("$TMP/temp", "hello");


    # list of files in $DIR (1 level)
        for (File::list($DIR)) {
            say $_->remotepath;
        }


    # list of all files in dir and subdir of $DIR
        File::walk(sub { say $_->remotepath }, File::tree($DIR));

=cut

1;
