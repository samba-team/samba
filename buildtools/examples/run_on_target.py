#!/usr/bin/env python3

#
# Sample run-on-target script
# This is a script that can be used as cross-execute parameter to samba
# configuration process, running the command on a remote target for which
# the cross-compiled configure test was compiled.
#
# To use:
# ./configure \
# --cross-compile \
# '--cross-execute=./buildtools/example/run_on_target.py --host=<host>'
#
# A more elaborate example:
# ./configure \
# --cross-compile \
# '--cross-execute=./buildtools/example/run_on_target.py --host=<host> --user=<user> "--ssh=ssh -i <some key file>" --destdir=/path/to/dir'
#
# Typically this is to be used also with --cross-answers, so that the
# cross answers file gets built and further builds can be made without
# the help of a remote target.
#
# The following assumptions are made:
# 1. rsync is available on build machine and target machine
# 2. A running ssh service on target machine with password-less shell login
# 3. A directory writable by the password-less login user
# 4. The tests on the target can run and provide reliable results
#    from the login account's home directory. This is significant
#    for example in locking tests which
#    create files in the current directory. As a workaround to this
#    assumption, the TESTDIR environment variable can be set on the target
#    (using ssh command line or server config) and the tests shall
#    chdir to that directory.
#

import sys
import os
import subprocess
from optparse import OptionParser

# those are defaults, but can be overidden using command line
SSH = 'ssh'
USER = None
HOST = 'localhost'


def xfer_files(ssh, srcdir, host, user, targ_destdir):
    """Transfer executable files to target

    Use rsync to copy the directory containing program to run
    INTO a destination directory on the target. An exact copy
    of the source directory is created on the target machine,
    possibly deleting files on the target machine which do not
    exist on the source directory.

    The idea is that the test may include files in addition to
    the compiled binary, and all of those files reside alongside
    the binary in a source directory.

    For example, if the test to run is /foo/bar/test and the
    destination directory on the target is /tbaz, then /tbaz/bar
    on the target shall be an exact copy of /foo/bar on the source,
    including deletion of files inside /tbaz/bar which do not exist
    on the source.
    """

    userhost = host
    if user:
        userhost = '%s@%s' % (user, host)

    cmd = 'rsync --verbose -rl --ignore-times --delete -e "%s" %s %s:%s/' % \
          (ssh, srcdir, userhost, targ_destdir)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    if p.returncode != 0:
        raise Exception('failed syncing files\n stdout:\n%s\nstderr:%s\n'
                        % (out, err))


def exec_remote(ssh, host, user, destdir, targdir, prog, args):
    """Run a test on the target

    Using password-less ssh, run the compiled binary on the target.

    An assumption is that there's no need to cd into the target dir,
    same as there's no need to do it on a native build.
    """
    userhost = host
    if user:
        userhost = '%s@%s' % (user, host)

    cmd = '%s %s %s/%s/%s' % (ssh, userhost, destdir, targdir, prog)
    if args:
        cmd = cmd + ' ' + ' '.join(args)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (p.returncode, out)


def main(argv):
    usage = "usage: %prog [options] <prog> [args]"
    parser = OptionParser(usage)

    parser.add_option('--ssh', help="SSH client and additional flags",
                      default=SSH)
    parser.add_option('--host', help="target host name or IP address",
                      default=HOST)
    parser.add_option('--user', help="login user on target",
                      default=USER)
    parser.add_option('--destdir', help="work directory on target",
                      default='~')

    (options, args) = parser.parse_args(argv)
    if len(args) < 1:
        parser.error("please supply test program to run")

    progpath = args[0]

    # assume that a test that was not compiled fails (e.g. getconf)
    if progpath[0] != '/':
        return (1, "")

    progdir = os.path.dirname(progpath)
    prog = os.path.basename(progpath)
    targ_progdir = os.path.basename(progdir)

    xfer_files(
        options.ssh,
        progdir,
        options.host,
        options.user,
        options.destdir)

    (rc, out) = exec_remote(options.ssh,
                            options.host,
                            options.user,
                            options.destdir,
                            targ_progdir,
                            prog, args[1:])
    return (rc, out)


if __name__ == '__main__':
    (rc, out) = main(sys.argv[1:])
    sys.stdout.write(out)
    sys.exit(rc)
