#!/usr/bin/perl

=head1 NAME

test_smbclient_tarmode.pl - Test for smbclient tar backup feature

=cut

# flags to test

# c        DONE
# c g      DONE
# c a      DONE
# c N      DONE
# c I      #
# c I r    #
# c X      #
# c X r    #
# c F      #
# c F r    #
# x        DONE
# x I      #
# x I r    #
# x X      #
# x X r    #
# x F      #
# x F r    #

use v5.16;
use strict;
use warnings;

use Archive::Tar;
use Data::Dumper;
use File::Path qw/make_path remove_tree/;
use Getopt::Long;
use Pod::Usage;
use Term::ANSIColor;

sub d {print Dumper @_;}

# DEFAULTS
our $USER      = '';
our $PW        = '';
our $HOST      = 'localhost';
our $IP        = '';
our $SHARE     = 'public';
our $DIR       = 'tarmode';
our $LOCALPATH = '/media/data/smb-test';
our $TMP       = '/tmp/smb-tmp';
our $BIN       = 'smbclient';

our @SMBARGS   = ();

our $DEBUG = 0;
our $MAN   = 0;
our $HELP  = 0;

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
    [\&test_creation_normal, 'normal'],
    [\&test_creation_normal, 'nested'],
    [\&test_creation_incremental, '-g'],
    [\&test_creation_incremental, 'tarmode inc'],
    [\&test_creation_reset,       '-a'],
    [\&test_creation_reset,       'tarmode reset'],
    [\&test_creation_newer],
    [\&test_extraction_normal],
);

#####

# TEST DEFINITIONS
# each test must return the number of error

sub test_creation_newer {

    say "TEST: creation -- backup files newer than a file";

    my @files;
    my $dt = 3000;

    # create oldest file at - DT
    my $oldest = File->new_remote('oldest');
    $oldest->set_attr();
    $oldest->set_time(time - $dt);

    # create limit file
    my $limit = File->new_local("$TMP/limit");

    # create newA file at + DT
    my $newA = File->new_remote('newA');
    $newA->set_attr();
    $newA->set_time(time + $dt);

    # create newB file at + DT
    my $newB = File->new_remote('newB');
    $newB->set_attr();
    $newB->set_time(time + $dt);

    # get files newer than limit_file
    push @files, $newA, $newB;

    smb_tar('', '-TcN', $limit->localpath, $TAR, $DIR);
    return check_tar($TAR, \@files);
}

sub test_creation_reset {
    my ($mode) = @_;

    say "TEST: creation -- reset archived files w/ $mode";

    my @files;
    my $n = 3;
    for(1..$n) {
        my $f = File->new_remote("file-$_");
        $f->set_attr('a');
        push @files, $f;
    }

    if($mode =~ /reset/) {
        smb_tar('tarmode full reset', '-Tc', $TAR, $DIR);
    } else {
        smb_tar('', '-Tca', $TAR, $DIR);
    }

    my $err = check_tar($TAR, \@files);
    return $err if($err > 0);

    for my $f (File->list()) {
        if($f->{attr}{a}) {
            printf " ! %s %s\n", $f->attr_str, $f->remotepath;
            $err++;
        }
    }
    return $err;
}

sub test_creation_normal {
    my ($mode) = @_;

    say "TEST: creation -- normal files $mode (no attributes)";

    my $prefix = ($mode =~ /nest/) ? "/foo/bar/bar/" : '';
    my @files;
    my $n = 5;
    for(1..$n) {
        my $f = File->new_remote($prefix."file-$_");
        $f->set_attr();
        push @files, $f;
    }

    smb_tar('tarmode full', '-Tc', $TAR, $DIR);
    return check_tar($TAR, \@files);
}

sub test_creation_incremental {
    my ($mode) = @_;

    say "TEST: creation -- incremental w/ $mode (backup only archived files)";

    my @files;
    my $n = 10;
    for(1..$n) {
        my $f = File->new_remote("file-$_");

        # set achive bit on ~half of them
        if($_ < $n/2) {
            $f->set_attr('a');
            push @files, $f;
        }
        else {
            $f->set_attr((qw/n r s h/)[$_ % 4]);
        }
    }

    if($mode =~ /inc/) {
        smb_tar('tarmode inc', '-Tc', $TAR, $DIR);
    } else {
        smb_tar('', '-Tcg', $TAR, $DIR);
    }
    return check_tar($TAR, \@files);
}


sub test_extraction_normal {

    say "TEST: extraction -- backup and restore normal files";

    my %files;
    my $n = 5;
    for(1..$n) {
        my $f = File->new_remote("file-$_");
        $f->set_attr();
        $files{$f->remotepath} = $f;
    }

    # store
    smb_tar('', '-Tc', $TAR, $DIR);
    my $err = check_tar($TAR, [values %files]);
    return $err if $err > 0;

    reset_remote();

    smb_tar('', '-Tx', $TAR);
    check_remote([values %files]);
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

sub reset_remote {
    remove_tree($LOCALPATH . '/'. $DIR);
    make_path($LOCALPATH . '/'. $DIR);
}

sub reset_tmp {
    remove_tree($TMP);
    make_path($TMP);
}

sub reset_env {
    reset_tmp();
    reset_remote();
}

sub check_remote {
    my ($files) = @_;
    my (%done, %expected);
    my (@less, @more, @diff);

    for(@$files) {
        $expected{$_->remotepath} = $_;
        $done{$_->remotepath} = 0;
    }

    my %remote;
    File::walk(sub { $remote{$_->remotepath} = $_ }, File::tree());

    for my $rfile (keys %remote) {

        # files that shouldn't be there
        if(!exists $expected{$rfile}) {
            say " +    $_";
            push @more, $rfile;
            next;
        }

        # same file multiple times
        if($done{$rfile} > 0) {
            $done{$rfile}++;
            push @more, $rfile;
            printf " +%3d %s\n", $done{$rfile}, $rfile;
            next;
        }

        $done{$rfile}++;

        # different file
        my $rmd5 = $remote{$rfile}->md5;
        if($expected{$rfile}->md5 ne $rmd5) {
            say " !    $rfile ($rmd5)";
            push @diff, $rfile;
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

sub check_tar {
    my ($tar, $files) = @_;
    my %done;
    my (@less, @more, @diff);

    my %h;

    for(@$files) {
        $h{$_->tarpath} = $_;
        $done{$_->tarpath} = 0;
    }

    my $i = Archive::Tar->iter($tar, 1, {md5 => 1});
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
            if($md5 ne $h{$p}->md5) {
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

sub random {
    my ($min, $max) = @_;
    ($min, $max) = ($max, $min) if($min > $max);
    $min + int(rand($max - $min));
}

package File;
use File::Basename;
use File::Path qw/make_path remove_tree/;
use Digest::MD5 qw/md5_hex/;

sub create_file {
    my $fn = shift;
    my $buf = '';
    unlink $fn if -e $fn;
    my $size = main::random(512, 1024);
    open my $out, '>', $fn or die "can't open $fn: $!\n";
    binmode $out;
    for(1..$size) {
        $buf .= pack('C', main::random(0, 256));
    }
    print $out $buf;
    close $out;
    return md5_hex($buf);
}

sub localpath {
    my $s = shift;
    return $s->{dir}.'/'.$s->{name} if !$s->{remote};
    $main::LOCALPATH.'/'.$s->remotepath;
}

sub remotepath {
    my ($s, $subpath) = @_;
    return undef if !$s->{remote};

    my $prefix = $main::DIR.'/';;

    if($subpath) {
        $prefix = '';
    }

    if($s->{dir}) {
        $prefix.$s->{dir}.'/'.$s->{name};
    } else {
        $prefix.$s->{name};
    }
}

sub remotedir {
    my $s = shift;
    return undef if !$s->{remote};
    $main::DIR.'/'.$s->{dir};
}

sub tarpath {
    my $s = shift;
    return undef if !$s->{remote};
    './'.$s->remotepath;
}

sub set_attr {
    my ($s, @flags) = @_;
    return undef if !$s->{remote};

    $s->{attr} = {qw/r 0 s 0 h 0 a 0 d 0 n 0/};

    for(@flags) {
        $s->{attr}{lc($_)} = 1;
    }

    my $file = $s->{name};
    main::smb_client('-D', $s->remotedir, '-c', qq{setmode "$file" -rsha});
    if(@flags && $flags[0] !~ /n/i) {
        main::smb_client('-D', $s->remotedir, '-c', qq{setmode "$file" +}.join('', @flags));
    }
}

sub attr_str {
    my $s = shift;
    return undef if !$s->{remote};
    join('', map {$_ if $s->{attr}{$_}} qw/r h s a d n/);
}


sub set_time {
    my ($s, $t) = @_;
    utime $t, $t, $s->localpath;
}

sub md5 {
    my $s = shift;

    if(!$s->{md5}) {
        open my $h, '<', $s->localpath() or die "can't read ".$s->localpath.": $!";
        binmode $h;
        $s->{md5} = Digest::MD5->new->addfile($h)->hexdigest;
        close $h;
    }

    return $s->{md5};
}

sub walk {
    my $fun = \&{shift @_};

    my @res;

    for (@_) {
        if($_->{attr}{d}) {
            push @res, walk($fun, @{$_->{content}});
        } else {
            push @res, $fun->($_);
        }
    }

    return @res;
}

sub tree {
    my ($class, $d) = @_;
    my @files;

    if(!defined $d) {
        @files = File->list();
    } else {
        @files = File->list($d->remotepath(1));
    }

    for my $f (@files) {
        if($f->{attr}{d}) {
            $f->{content} = [tree($class, $f)];
        }
    }

    return @files;
}

sub list {
    my ($class, $path) = @_;
    $path ||= '';
    $path =~ s{/$}{};
    my @files;
    my $out = main::smb_client('-D', $main::DIR.'/'.$path, '-c', 'ls');

    for(split /\n/, $out) {
        next if !/^  (.+?)\s+([AHSRDN]+)\s+(\d+)\s+(.+)/o;
        my ($fn, $attr, $size, $date) = ($1, $2, $3, $4);
        next if $fn =~ /^\.{1,2}$/;

        push @files, bless {
            'remote' => 1,
            'dir'    => $path,
            'name'   => $fn,
            'size'   => int($size),
            'date'   => $date,
            'attr'   => {
                # list context returns somehting different than the
                # boolean matching result => force scalar context
                'a' => scalar ($attr =~ /A/),
                'h' => scalar ($attr =~ /H/),
                's' => scalar ($attr =~ /S/),
                'r' => scalar ($attr =~ /R/),
                'd' => scalar ($attr =~ /D/),
                'n' => scalar ($attr =~ /N/),
            },
        }, $class;
    }
    return @files;
}

sub new_remote {
    my ($class, $path) = @_;
    my ($file, $dir) = fileparse($path);

    $dir = '' if $dir eq './';
    $dir =~ s{^/}{};
    $dir =~ s{/$}{};

    my $loc = $main::LOCALPATH.'/'.$main::DIR.'/'.$dir;
    make_path($loc);

    my $self = {
        'attr' => {qw/r 0 s 0 h 0 a 0 d 0 n 0/},
        'dir'  => $dir,
        'name' => $file,
        'md5'  => create_file($loc.'/'.$file),
        'remote' => 1,
    };

    bless $self, $class;
}

sub new_local {
    my ($class, $path) = @_;
    my ($file, $dir) = fileparse($path);

    $dir =~ s{/$}{};
    make_path($dir);

    my $self = {
        'attr' => {qw/r 0 s 0 h 0 a 0 d 0 n 0/},
        'dir'  => $dir,
        'name' => $file,
        'md5'  => create_file($path),
        'remote' => 0,
    };

    bless $self, $class;
}

1;
