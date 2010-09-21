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

f = subprocess.Popen(["ssh", opts.host, "mktemp", "-d"], stdout=subprocess.PIPE)
(stdout, stderr) = f.communicate()
remote_tmpdir = stdout.rstrip()

print "Remote tempdir: %s" % remote_tmpdir

if subprocess.call(["ssh", opts.host, "git", "clone", "git://git.samba.org/samba.git", "%s/repo" % remote_tmpdir]) != 0:
    sys.exit(1)

print "Pushing local branch"
subprocess.call(["git", "push", "--force", "git+ssh://%s/%s/repo" % (opts.host, remote_tmpdir), "HEAD:refs/heads/land"])
args = ["ssh", "-A", opts.host, "python", "%s/repo/source4/script/land.py" % remote_tmpdir]
if opts.mail_to:
    args.append("--mail-to=%s" % opts.mail_to)
if not opts.foreground:
    args.append("--daemon")
if opts.dry_run:
    args.append("--dry-run")
args.append("--branch=land")
args.append(os.path.join(remote_tmpdir, "repo"))
print "Running remotely: %s" % " ".join(args)
sys.exit(subprocess.call(args))
