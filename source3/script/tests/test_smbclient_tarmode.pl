#!/usr/bin/perl

=head1 NAME

test_smbclient_tarmode.pl - Test for smbclient tar backup feature

=cut

use v5.16;
use strict;
use warnings;

use Archive::Tar;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use File::Basename;
use File::Path qw/make_path remove_tree/;
use Getopt::Long;
use Pod::Usage;
use Term::ANSIColor;

sub d {print Dumper @_;}

# DEFAULTS
my $USER      = '';
my $PW        = '';
my $HOST      = 'localhost';
my $IP        = '';
my $SHARE     = 'public';
my $DIR       = 'tarmode';
my $LOCALPATH = '/media/data/smb-test';
my $TMP       = '/tmp/smb-tmp';
my $BIN       = 'smbclient';

my @SMBARGS   = ();

my $DEBUG = 0;
my $MAN   = 0;
my $HELP  = 0;

=head1 SYNOPSIS

test_smbclient_tarmode.pl [options] -- [smbclient options]

 Options:
    -h, --help    brief help message
    --man         full documentation

    -u, --user      USER
    -p, --password  PW
    -h, --host      HOST
    -i, --ip        IP
    -s, --share     SHARE
    -d, --dir       PATH
        sub-path to use on the share

    -l, --local-path  PATH
        path to the root of the samba share on the machine.

    -t, --tmp  PATH
        temporary dir to use

    -b, --bin  BIN
        path to the smbclient binary to use

=cut

GetOptions('u|user=s'       => \$USER,
           'p|password=s'   => \$PW,
           'h|host=s'       => \$HOST,
           'i|ip=s'         => \$IP,
           's|share=s'      => \$SHARE,
           'd|dir=s'        => \$DIR,
           'l|local-path=s' => \$LOCALPATH,
           't|tmp=s'        => \$TMP,
           'b|bin=s'        => \$BIN,

           'debug'          => \$DEBUG,
           'h|help'         => \$HELP,
           'man'            => \$MAN) or pod2usage(2);

pod2usage(0) if $HELP;
pod2usage(-exitval => 0, -verbose => 2) if $MAN;

if($USER xor $PW) {
    die "Need both user and password when one is provided\n";
} elsif($USER and $PW) {
    push @SMBARGS, '-U'.$USER.'%'.$PW;
} else {
    push @SMBARGS, '-N';
}

if($IP) {
    push @SMBARGS, '-I', $IP;
}

# remaining arguments are passed to smbclient
push @SMBARGS, @ARGV;

# path to store the downloaded tarball
my $TAR = "$TMP/tarmode.tar";

#####

# RUN TESTS

run_test(
    [\&test_creation_normal],
    [\&test_creation_incremental, '-g'],
    [\&test_creation_incremental, 'tarmode inc'],
    [\&test_creation_reset,       '-a'],
    [\&test_creation_reset,       'tarmode reset'],
    [\&test_creation_newer],
);

#####

# TEST DEFINITIONS
# each test must return the number of error

sub test_creation_newer {

    say "TEST: creation -- backup files newer than a file";

    my %files;
    my $dt = 3000;

    # create oldest file at - DT
    my $oldest_file = "oldest";
    my $oldest_md5 = create_file(localpath($oldest_file));
    set_attr(remotepath($oldest_file));
    set_time(localpath($oldest_file), time - $dt);

    # create limit file
    my $limit_file = "$TMP/limit";
    create_file($limit_file);

    # create newA file at + DT
    my $newA_file = "newA";
    my $newA_md5 = create_file(localpath($newA_file));
    set_attr(remotepath($newA_file));
    set_time(localpath($newA_file), time + $dt);

    # create newB file at + DT
    my $newB_file = "newB";
    my $newB_md5 = create_file(localpath($newB_file));
    set_attr(remotepath($newB_file));
    set_time(localpath($newB_file), time + $dt);

    # get files newer than limit_file
    $files{"./$DIR/$newA_file"} = $newA_md5;
    $files{"./$DIR/$newB_file"} = $newB_md5;

    smb_tar('', '-TcN', $limit_file, $TAR, $DIR);
    return check_tar($TAR, \%files);
}

sub test_creation_reset {
    my ($mode) = @_;

    say "TEST: creation -- reset archived files w/ $mode";

    my %files;
    my $n = 3;
    for(1..$n) {
        my $f = "file-$_";
        my $md5 = create_file(localpath($f));
        $files{"./$DIR/$f"} = $md5;
        set_attr(remotepath($f), 'a');
    }

    if($mode =~ /reset/) {
        smb_tar('tarmode full reset', '-Tc', $TAR, $DIR);
    } else {
        smb_tar('', '-Tca', $TAR, $DIR);
    }
    my $err = check_tar($TAR, \%files);
    return $err if($err > 0);

    for my $f (smb_ls($DIR)) {
        if($f->{attr}{A}) {
            my $attr = join('', map {$_ if $f->{attr}{$_}} qw/R H S A N D/);
            printf " ! %s %s\n", $attr, $f->{path}.'/'.$f->{fn};
            $err++;
        }
    }
    return $err;
}

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
    my $n = 10;
    for(1..$n) {
        my $f = "file-$_";
        my $md5 = create_file(localpath($f));

        # set achive bit on ~half of them
        if($_ < $n/2) {
            $files{"./$DIR/$f"} = $md5;
            set_attr(remotepath($f), 'a');
        }
        else {
            set_attr(remotepath($f), ((qw/n r s h/)[$_ % 4]))
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
    reset_env();
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
    my (@args) = @_;

    my $fullpath = "//$HOST/$SHARE";
    my $cmd = sprintf("%s %s %s",
                      quotemeta($BIN),
                      quotemeta($fullpath),
                      join(' ', map {quotemeta} (@SMBARGS, @args)));

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

    if($DEBUG) {
        $cmd =~ s{\\([/+-])}{$1}g;
        say $cmd;
        say $out;
    }

    if($err) {
        say "ERROR";
        say $out;
        exit 1;
    }
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
                # list context returns somehting different than the
                # boolean matching result => force scalar context
                'A' => scalar ($attr =~ /A/),
                'H' => scalar ($attr =~ /H/),
                'S' => scalar ($attr =~ /S/),
                'R' => scalar ($attr =~ /R/),
                'D' => scalar ($attr =~ /D/),
                'N' => scalar ($attr =~ /N/),
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
    if(@flags && $flags[0] !~ /n/i) {
        smb_client('-D', $dir, '-c', qq{setmode "$file" +}.join('', @flags));
    }
}

sub get_file {
    my ($fullpath, @flags) = @_;
    my ($file, $dir) = fileparse($fullpath);

    my @files = smb_ls($dir);
    my @res = grep {$_->{fn} eq $file} @files;
    return @res ? $res[0] : undef;
}

sub random {
    my ($min, $max) = @_;
    ($min, $max) = ($max, $min) if($min > $max);
    $min + int(rand($max - $min));
}

sub set_time {
    my ($fn, $t) = @_;
    utime $t, $t, $fn;
}
