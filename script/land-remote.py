#!/usr/bin/python
# Ship a local branch to a remote host (sn-104?) over ssh and run autobuild in it.
# Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
# Published under the GPL, v3 or later

import optparse
import subprocess
import sys

parser = optparse.OptionParser("autoland-remote [options] [trees...]")
parser.add_option("--remote-repo", help="Location of remote repository (default: temporary repository)", type=str, default=None)
parser.add_option("--host", help="Host to land on (SSH connection string)", type=str, default="sn-devel-104.sn.samba.org")
parser.add_option("--foreground", help="Don't daemonize", action="store_true", default=False)
parser.add_option("--email", help="Email address to send build/test output to", type=str, default=None, metavar="EMAIL")
parser.add_option("--always-email", help="always send email, even on success", action="store_true")
parser.add_option("--rebase-master", help="rebase on master before testing", default=False, action='store_true')
parser.add_option("--rebase", help="rebase on the given tree before testing", default=None, type='str')
parser.add_option("--passcmd", help="command to run on success", default=None)
parser.add_option("--tail", help="show output while running", default=False, action="store_true")
parser.add_option("--keeplogs", help="keep logs", default=False, action="store_true")
parser.add_option("--nocleanup", help="don't remove test tree", default=False, action="store_true")
parser.add_option("--fix-whitespace", help="fix whitespace on rebase",
                  default=False, action="store_true")
parser.add_option("--fail-slowly", help="continue running tests even after one has already failed",
                  action="store_true")

(opts, extra_args) = parser.parse_args()

if not opts.foreground and not opts.email:
    print "Not running in foreground and --email not specified."
    sys.exit(1)

if not opts.remote_repo:
    print "%s$ mktemp -d" % opts.host
    f = subprocess.Popen(["ssh", opts.host, "mktemp", "-d"], stdout=subprocess.PIPE)
    (stdout, stderr) = f.communicate()
    if f.returncode != 0:
        sys.exit(1)
    remote_repo = stdout.rstrip()
    print "Remote tempdir: %s" % remote_repo
    # Bootstrap, git.samba.org is close to sn-devel
    remote_args = ["git", "clone", "git://git.samba.org/samba.git", remote_repo]
    #remote_args = ["git", "init", remote_repo]
    print "%s$ %s" % (opts.host, " ".join(remote_args))
    subprocess.check_call(["ssh", opts.host] + remote_args)
else:
    remote_repo = opts.remote_repo

print "Pushing local branch"
args = ["git", "push", "--force", "git+ssh://%s/%s" % (opts.host, remote_repo), "HEAD:land"]
print "$ " + " ".join(args)
subprocess.check_call(args)
remote_args = ["cd", remote_repo, ";", "git", "checkout", "land", ";", "./script/land.py", "--repository=%s" % remote_repo]
if opts.email:
    remote_args.append("--email=%s" % opts.email)
if opts.always_email:
    remote_args.append("--always-email")
if not opts.foreground:
    remote_args.append("--daemon")
if opts.nocleanup:
    remote_args.append("--nocleanup")
if opts.fix_whitespace:
    remote_args.append("--fix-whitespace")
if opts.tail:
    remote_args.append("--tail")
if opts.keeplogs:
    remote_args.append("--keeplogs")
if opts.rebase_master:
    remote_args.append("--rebase-master")
if opts.rebase:
    remote_args.append("--rebase=%s" % opts.rebase)
if opts.passcmd:
    remote_args.append("--passcmd=%s" % opts.passcmd)
remote_args += extra_args
print "%s$ %s" % (opts.host, " ".join(remote_args))
args = ["ssh", "-A", opts.host] + remote_args
sys.exit(subprocess.call(args))
