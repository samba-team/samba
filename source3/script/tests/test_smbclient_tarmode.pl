#!/usr/bin/perl

=head1 NAME

test_smbclient_tarmode.pl - Test for smbclient tar backup feature

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
our $DIR       = 'tar_test_dir';
our $LOCALPATH = '/media/data/smb-test';
our $TMP       = '/tmp/smb-tmp';
our $BIN       = 'smbclient';

our $SINGLE_TEST = -1;

our @SMBARGS   = ();

our $DEBUG = 0;
our $MAN   = 0;
our $HELP  = 0;
our $CLEAN = 0;

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

    -t, --tmp  PATH
        temporary dir to use

    -b, --bin  BIN
        path to the smbclient binary to use

  Test:
    --test N
       only run test number N

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

           'test=i'         => \$SINGLE_TEST,

           'clean'          => \$CLEAN,
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

if($CLEAN) {
    # clean the whole root first
    remove_tree($LOCALPATH, { keep_root => 1 });
}

#####

# RUN TESTS

my @all_tests = (
    [\&test_creation_normal, 'normal'],
    [\&test_creation_normal, 'nested'],
    [\&test_creation_incremental, '-g'],
    [\&test_creation_incremental, 'tarmode inc'],
    [\&test_creation_reset,       '-a'],
    [\&test_creation_reset,       'tarmode reset'],
    [\&test_creation_newer],
    [\&test_creation_attr],
    [\&test_creation_include,],
    [\&test_creation_exclude,],
    [\&test_creation_list,],
    [\&test_creation_wildcard],
    [\&test_extraction_normal],
    [\&test_extraction_include],
    [\&test_extraction_exclude],
    [\&test_extraction_list],
    [\&test_extraction_wildcard],
);

if($SINGLE_TEST == -1) {
    run_test(@all_tests);
}

elsif(0 <= $SINGLE_TEST&&$SINGLE_TEST < @all_tests) {
    run_test($all_tests[$SINGLE_TEST]);
}

else {
    die "Test number is invalid\n";
}

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

sub test_creation_attr {

    say "TEST: creation -- combinations of tarmodes (nosystem, nohidden, etc)";

    my @attr = qw/r h s a/;
    my @all;
    my @inc;
    my $err = 0;

    # one normal file
    my $f = File->new_remote("file-n.txt");
    $f->set_attr();
    push @all, $f;

    # combinaisions of attributes
    for my $n (1..@attr) {
        for(combine(\@attr, $n)) {
            my @t = @$_;
            my $fn = "file-" . join('+', @t) . ".txt";
            my $f = File->new_remote($fn);
            $f->set_attr(@t);
            push @all, $f;
        }
    }

    @inc = grep { !$_->{attr}{s} } @all;
    smb_tar('tarmode nosystem', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    @inc = grep { !$_->{attr}{h} } @all;
    smb_tar('tarmode nohidden', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    @inc = grep { !$_->{attr}{h} and !$_->{attr}{s} } @all;
    smb_tar('tarmode nohidden nosystem', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    @inc = grep { $_->{attr}{a} and !$_->{attr}{h} and !$_->{attr}{s} } @all;
    smb_tar('tarmode inc nohidden nosystem', '-Tc', $TAR, $DIR);
    $err += check_tar($TAR, \@inc);

    $err;
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

    for my $f (File->list($DIR)) {
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

    my @files;
    my $n = 5;
    for(1..$n) {
        my $f = File->new_remote("file-$_");
        $f->set_attr();
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

    say "TEST: extraction -- backup and restore included paths";

    my @all_files;
    my @inc_files;

    for(qw(file_inc inc/b inc/c inc/dir/foo dir_ex/d zob)) {
        my $f = File->new_remote($_);
        $f->set_attr();
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

    say "TEST: extraction -- backup and restore without excluded paths";

    my @all_files;
    my @inc_files;

    for(qw(file_exc exc/b exc/c exc/dir/foo dir_ex/d zob)) {
        my $f = File->new_remote($_);
        $f->set_attr();
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
    say "TEST: extraction -- explicit include";

    my @files;

    for(qw(file_inc inc/b inc/c inc/dir/foo dir_ex/d zob)) {
        my $f = File->new_remote($_);
        $f->set_attr();
        push @files, $f if /inc/;
    }

    smb_tar('', '-TcI', $TAR, "$DIR/file_inc", "$DIR/inc");
    return check_tar($TAR, \@files);
}

sub test_creation_exclude {
    say "TEST: extraction -- explicit exclude";

    my @files;

    for(qw(file_ex ex/b ex/c ex/dir/foo foo/bar zob)) {
        my $f = File->new_remote($_);
        $f->set_attr();
        push @files, $f if !/ex/;
    }

    smb_tar('', '-TcX', $TAR, "$DIR/file_ex", "$DIR/ex");
    return check_tar($TAR, \@files);
}

sub test_creation_list {
    say "TEST: creation -- filelist";

    my @inc_files;

    for(qw(file_inc inc/b inc/c inc/dir/foo foo/bar zob)) {
        my $f = File->new_remote($_);
        $f->set_attr();
        push @inc_files, $f if /inc/;
    }

    my $flist = File->new_local("$TMP/list", file_list(@inc_files));
    smb_tar('', '-TcF', $TAR, $flist->localpath);
    return check_tar($TAR, \@inc_files);
}

sub tardump {
    system sprintf q{tar tf %s 2>&1 | grep -v '/$' | sort }, $TAR;
}

sub test_creation_wildcard {
    say "TEST: creation -- include/exclude with wildcards";

    my @exts = qw(txt jpg exe);
    my @dirs = ('', "$DIR/", "$DIR/dir/");
    my @all;
    my $nb;
    my $err = 0;

    $nb = 0;
    for my $dir (@dirs) {
        for(@exts) {
            my $fn = $dir . "file$nb." . $_;
            my $f = File->new_remote($fn, 'ABSPATH');
            $f->delete_on_destruction(1);
            $f->set_attr();
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
    say "TEST: extraction -- include/exclude with wildcards";

    my @exts = qw(txt jpg exe);
    my @dirs = ('', "$DIR/", "$DIR/dir/");
    my $nb;
    my $err = 0;

    for my $dir (@dirs) {

        my @all;

        $nb = 0;
        for my $dir (@dirs) {
            for(@exts) {
                my $fn = $dir . "file$nb." . $_;
                my $f = File->new_remote($fn, 'ABSPATH');
                $f->delete_on_destruction(1);
                $f->set_attr();
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
    say "TEST: extraction -- filelist";

    my @inc_files;
    my @all_files;

    for(qw(file_inc inc/b inc/c inc/dir/foo foo/bar zob)) {
        my $f = File->new_remote($_);
        $f->set_attr();
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

# return list of combinations of n-uplet
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

sub file_list {
    my @files = @_;
    my $s = '';
    for(@files) {
        $s .= $_->remotepath."\n";
    }
    return $s;
}

sub check_remote {
    my ($subpath, $files) = @_;
    my (%done, %expected);
    my (@less, @more, @diff);

    for(@$files) {
        $expected{$_->remotepath} = $_;
        $done{$_->remotepath} = 0;
    }

    my %remote;
    File::walk(sub { $remote{$_->remotepath} = $_ }, File::tree($subpath));

    for my $rfile (keys %remote) {

        # files that shouldn't be there
        if(!exists $expected{$rfile}) {
            say " +    $rfile";
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
            next;
        }

        if($DEBUG) {
            say "      $rfile";
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

    my $total = 0;
    my $i = Archive::Tar->iter($tar, 1, {md5 => 1});
    while(my $f = $i->()) {
        if($f->has_content) {
            $total++;
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
                next;
            }

            if($DEBUG) {
                say "      $p";
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
           $total,
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

    if($DEBUG) {
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

    if($DEBUG) {
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
use Scalar::Util 'blessed';

sub cleanpath {
    my $p = shift;
    $p =~ s{/+}{/}g;
    $p =~ s{/$}{};
    $p;
}

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
    if($s->{remote}) {
        return cleanpath($main::LOCALPATH.'/'.$s->remotepath);
    }
    else {
        return cleanpath($s->{dir}.'/'.$s->{name});
    }
}

sub remotepath {
    my ($s) = @_;
    return undef if !$s->{remote};
    cleanpath(($s->{dir}.'/'.$s->{name}) =~ s{^/}{}r);
}

sub remotedir {
    my $s = shift;
    return undef if !$s->{remote};
    cleanpath($s->{dir});
}

sub tarpath {
    my $s = shift;
    return undef if !$s->{remote};
    cleanpath('./'.$s->remotepath);
}

sub delete_on_destruction {
    my ($s, $delete) = @_;
    $s->{delete_on_destruction} = $delete;
}

sub set_attr {
    my ($s, @flags) = @_;
    return undef if !$s->{remote};

    $s->{attr} = {qw/r 0 s 0 h 0 a 0 d 0 n 0/};

    for(@flags) {
        $s->{attr}{lc($_)} = 1;
    }

    my $file = $s->{name};
    my @args;
    if($s->remotedir) {
        push @args, '-D', $s->remotedir;
    }
    main::smb_client(@args, '-c', qq{setmode "$file" -rsha});
    if(@flags && $flags[0] !~ /n/i) {
        main::smb_client(@args, '-c', qq{setmode "$file" +}.join('', @flags));
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
    } elsif(blessed $d) {
        @files = File->list($d->remotepath);
    } else {
        @files = File->list($d);
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
    $path ||= '/';
    my @files;
    my $out = main::smb_client('-D', $path, '-c', 'ls');

    for(split /\n/, $out) {
        next if !/^  (.+?)\s+([AHSRDN]+)\s+(\d+)\s+(.+)/o;
        my ($fn, $attr, $size, $date) = ($1, $2, $3, $4);
        next if $fn =~ /^\.{1,2}$/;

        push @files, bless {
            'remote' => 1,
            'dir'    => $path =~ s{^/}{}r,
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
    my ($class, $path, $abs) = @_;
    my ($file, $dir) = fileparse($path);

    $dir = '' if $dir eq './';
    my $loc;

    if($abs) {
        $loc = cleanpath($main::LOCALPATH.'/'.$dir);
    } else {
        $dir = cleanpath($main::DIR.'/'.$dir);
        $loc = cleanpath($main::LOCALPATH.'/'.$dir);
    }

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
    my ($class, $path, $data) = @_;
    my ($file, $dir) = fileparse($path);

    make_path($dir);

    my $md5;

    if(defined $data) {
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

# a gate to hard to debug bugs...
sub DESTROY {
    my $s = shift;
    if($s->{delete_on_destruction} && -f $s->localpath) {
        if($main::DEBUG) {
            say "DESTROY ".$s->localpath;
        }
        unlink $s->localpath;
    }
}

1;
