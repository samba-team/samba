#!/usr/bin/perl
#
# The plan is to make a script which will test the behaviour of
# smbclient tar creation/restoration including its handling of:
# - the include/exclude list (resp. I and X)
# - the file list (F)
# - the regex switch (r) which change the behaviour of F, I and X
# - "newer than" (N)
# - tar modes (full, incremental, nosystem, nohidden)
# - archive bit removal (a)

# The script will work with samba itself since there's already code
# doing that (the "selftest" suite) but it could also work on an
# actual windows box if there's a way or some kind of framework to do
# some things remotely on it.

# For each creation (c) test:
# - setup the environnement (files and their attributes on the server)
# - fetch according to the test parameters
# - compare what the tarball contains vs. what's expected

# For each restoration (x) test:
# - setup empty environement
# - restore

# -aaptel

use v5.16;
use strict;
use warnings;

use Archive::Tar;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use File::Basename;
use File::Path qw/make_path remove_tree/;
use Getopt::Std;
use Term::ANSIColor;

sub d {print Dumper @_;}

my $SERVER    = $ARGV[0]; # XXX: ignored
my $IP        = $ARGV[1]; # XXX: ignored
my $USER      = $ARGV[2]; # XXX: ignored
my $PW        = $ARGV[3]; # XXX: ignored
my $LOCALPATH = $ARGV[4];
my $TMP       = $ARGV[5];
my $BIN       = $ARGV[6]; # XXX: valgrind?

# machine + share to test
my $SHARE = '//localhost/public';

# where the share is locally stored
$LOCALPATH //= '/media/data/smb-test';

# flags to pass to every smbclient calls
my @FLAGS = qw/-N/;

# smbclient binary to use (also look in PATH)
$BIN //= 'smbclient';

# temp dir to extract tar files
$TMP //= '/tmp/smb-tmp';
my $TAR = "$TMP/tarmode.tar";
my $DIR = 'tarmode';

#####

# RUN TESTS

run_test(
    [\&test_creation_normal],
    [\&test_creation_incremental, '-g'],
    [\&test_creation_incremental, 'tarmode inc'],
);

#####

# TEST DEFINITIONS
# each test must return the number of error

sub test_creation_normal {

    say "TEST: creation -- normal files (no attributes)";

    my %files;
    my $n = 5;
    for(1..$n) {
        my $f = "file-$_";
        my $md5 = create_file(localpath($f));
        $files{"./$DIR/$f"} = $md5;
        set_attr(remotepath($f));
    }

    smb_tar('tarmode full', '-Tc', $TAR, $DIR);
    return check_tar($TAR, \%files);
}


sub test_creation_incremental {
    my ($mode) = @_;

    say "TEST: creation -- incremental w/ $mode (backup only archived files)";

    my %files;
    my $n = 5;
    for(1..$n) {
        my $f = "file-$_";
        my $md5 = create_file(localpath($f));

        # set achive bit on ~half of them
        if($_ < $n/2) {
            $files{"./$DIR/$f"} = $md5;
            set_attr(remotepath($f), 'a');
        }
    }

    if($mode =~ /inc/) {
        smb_tar('tarmode inc', '-Tc', $TAR, $DIR);
    } else {
        smb_tar('', '-Tcg', $TAR, $DIR);
    }
    return check_tar($TAR, \%files);
}

#####

# IMPLEMENTATION

sub run_test {
    for(@_) {
        my ($f, @args) = @$_;
        reset_env();
        my $err = $f->(@args);
        print_res($err);
        print "\n";
    }
}

sub print_res {
    my $err = shift;
    if($err) {
        printf " RES: %s%d ERR%s\n", color('bold red'), $err, color 'reset';
    } else {
        printf " RES: %sOK%s\n", color('bold green'), color 'reset';
    }
}

sub reset_env {
    remove_tree($TMP);
    make_path($TMP, {mode => 0777});

    remove_tree($LOCALPATH . '/'. $DIR);
    make_path($LOCALPATH . '/'. $DIR, {mode => 0777});
}

sub check_tar {
    my ($fn, $files) = @_;
    my %done;
    my (@less, @more, @diff);

    for(keys %$files) {
        $done{$_} = 0;
    }

    my $i = Archive::Tar->iter($fn, 1, {md5 => 1});
    while(my $f = $i->()) {
        if($f->has_content) {
            my $p = $f->full_path;

            # file that shouldn't be there
            if(!exists $done{$p}) {
                push @more, $p;
                say " +    $p";
                next;
            }

            # same file multiple times
            if($done{$p} > 0) {
                $done{$p}++;
                push @more, $p;
                printf " +%3d %s\n", $done{$p}, $p;
                next;
            }

            $done{$p}++;

            # different file
            my $md5 = $f->data;
            if($md5 ne $$files{$p}) {
                say " !    $p ($md5)";
                push @diff, $p;
            }
        }
    }

    # file that should have been in tar
    @less = grep { $done{$_} == 0 } keys %done;
    for(@less) {
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

sub localpath {
    my $path = shift;
    $path = '/'.$path if $path !~ m~^/~;
    $LOCALPATH . '/' . $DIR . $path;
}

sub remotepath {
    my $path = shift;
    $path = '/'.$path if $path !~ m~^/~;
    $DIR . $path;
}


# call smbclient and return output
sub smb_client {
    my $cmd = sprintf("%s %s %s",
                      quotemeta($BIN),
                      quotemeta($SHARE),
                      join(' ', map {quotemeta} (@FLAGS, @_)));

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

    if($err) {
        d($out);
        exit 1;
    }
    #say $cmd;
    return $out;
}

sub smb_cmd {
    return smb_client('-c', join(' ', @_));
}

sub smb_tar {
    my ($cmd, @rest) = @_;
    printf " CMD: %s\n ARG: %s\n", $cmd, join(' ', @rest);
    smb_client((length($cmd) ? ('-c', $cmd) : ()), @rest);
}

# return a list of hash of a path on the share
# TODO: use recurse mode to make less smbclient calls
sub smb_ls {
    my $path = shift;
    my @files;
    my $out = defined $path && length($path)
        ? smb_client('-D', $path, '-c', 'ls')
        : smb_cmd('ls');

    for(split /\n/, $out) {
        next if !/^  (.+?)\s+([AHSRDN]+)\s+(\d+)\s+(.+)/o;
        my ($fn, $attr, $size, $date) = ($1, $2, $3, $4);
        next if $fn =~ /^\.{1,2}$/;
        push @files, {
            'path' => $path,
            'fn'   => $fn,
            'size' => int($size),
            'date' => $date,
            'attr' => {
                'A' => ($attr =~ /A/),
                'H' => ($attr =~ /H/),
                'S' => ($attr =~ /S/),
                'R' => ($attr =~ /R/),
                'D' => ($attr =~ /D/),
                'N' => ($attr =~ /N/),
            },
        };
    }
    return @files;
}

# recursively list the share and return it
sub smb_tree {
    my ($d, $path) = @_;
    my @files;

    if(!defined $d) {
        $d = {'fn' => '', 'attr' => {'D',1}};
        $path = '';
    }

    @files = smb_ls($path);
    $d->{dir} = [@files];

    for my $f (@files) {
        if($f->{attr}{D}) {
            smb_tree($f, $path.'/'.$f->{fn});
        }
    }
    return $d;
}

# print find(1)-like output of the share
# ex: dump_tree(smb_tree())
sub dump_tree {
    my ($t, $path) = @_;
    $path = '' if(!defined $path);

    for my $f (@{$t->{dir}}) {
        if($f->{attr}{D}) {
            # print final slash on dir
            print $path.'/'.$f->{fn},"/\n";
            dump_tree($f, $path.'/'.$f->{fn});
        } else {
            print $path.'/'.$f->{fn},"\n";
        }
    }
}

# create file with random content, return md5 sum
# ex: create_file('/path/on/disk')
sub create_file {
    my $fn = shift;
    my $buf = '';
    unlink $fn if -e $fn;
    my $size = random(512, 1024);
    open my $out, '>', $fn or die "can't open $fn: $!\n";
    binmode $out;
    for(1..$size) {
        $buf .= pack('C', random(0, 256));
    }
    print $out $buf;
    close $out;
    chmod 0666;
    return md5_hex($buf);
}

# set DOS attribute of a file
# remove all attr and add the one provided
# ex: set_attr('/path/on/share', 'r', 's')
sub set_attr {
    my ($fullpath, @flags) = @_;
    my ($file, $dir) = fileparse($fullpath);

    smb_client('-D', $dir, '-c', qq{setmode "$file" -rsha});
    if(@flags) {
        smb_client('-D', $dir, '-c', qq{setmode "$file" +}.join('', @flags));
    }
}

sub random {
    my ($min, $max) = @_;
    ($min, $max) = ($max, $min) if($min > $max);
     $min + int(rand($max - $min));
}
