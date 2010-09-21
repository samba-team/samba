#!/usr/bin/python
# Land a branch by building and testing it on sn-104 before landing it on master.
# Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
# Published under the GPL, v3 or later

import os
import optparse
import subprocess
import sys

parser = optparse.OptionParser("land-remote [options]")
parser.add_option("--host", help="Host to land on (SSH connection string)", type=str, default="sn-devel-104.sn.samba.org")
parser.add_option("--dry-run", help="Dry run (don't actually land)", action="store_true", default=False)
parser.add_option("--foreground", help="Don't daemonize", action="store_true", default=False)
parser.add_option("--mail-to", help="Email address to send build/test output to", type=str, default=None, metavar="MAIL-TO")

(opts, args) = parser.parse_args()

if not opts.foreground and not opts.mail_to:
    print "Not running in foreground and --mail-to not specified."
    sys.exit(1)

print "%s$ mktemp -d" % opts.host
f = subprocess.Popen(["ssh", opts.host, "mktemp", "-d"], stdout=subprocess.PIPE)
(stdout, stderr) = f.communicate()
if f.returncode != 0:
    sys.exit(1)
remote_tmpdir = stdout.rstrip()

print "Remote tempdir: %s" % remote_tmpdir

remote_args = ["git", "clone", "git://git.samba.org/samba.git", "%s/repo" % remote_tmpdir]
print "%s$ %s" % (opts.host, " ".join(remote_args))
subprocess.check_call(["ssh", opts.host] + remote_args)

print "Pushing local branch"
print "$ " + " ".join(args)
subprocess.check_call(["git", "push", "--force", "git+ssh://%s/%s/repo" % (opts.host, remote_tmpdir), "HEAD:refs/heads/land"])
remote_args = ["python", "%s/repo/source4/script/land.py" % remote_tmpdir]
if opts.mail_to:
    remote_args.append("--mail-to=%s" % opts.mail_to)
if not opts.foreground:
    remote_args.append("--daemon")
if opts.dry_run:
    remote_args.append("--dry-run")
remote_args.append("--branch=land")
remote_args.append(os.path.join(remote_tmpdir, "repo"))
print "%s$ %s" % (opts.host, " ".join(remote_args))
args = ["ssh", "-A", opts.host] + remote_args
sys.exit(subprocess.call(args))
