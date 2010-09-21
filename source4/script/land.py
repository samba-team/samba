#!/usr/bin/python
# Compile a Samba 4 branch from scratch and land it onto master.
# (C) 2010 Jelmer Vernooij <jelmer@samba.org>
# Published under the GPL, v3 or later.

from email.mime.text import MIMEText
import optparse
import os
import shutil
import smtplib
import subprocess
import sys
import tempfile

parser = optparse.OptionParser("land [options] <repo>")
parser.add_option("--branch", help="Branch to land", type=str, default=None, metavar="BRANCH")
parser.add_option("--dry-run", help="Dry run (don't actually land)", action="store_true", default=False)
parser.add_option("--daemon", help="Daemonize", action="store_true", default=False)
parser.add_option("--mail-to", help="Email address to send build/test output to", type=str, default=None, metavar="MAIL-TO")

(opts, args) = parser.parse_args()

if opts.mail_to:
    from_addr = opts.mail_to
    smtp = smtplib.SMTP()

if len(args) != 1:
    parser.print_usage()
    sys.exit(1)

[repo] = args
tmpdir = tempfile.mkdtemp()
rootpath = os.path.join(tmpdir, "repo")

if subprocess.call(["git", "clone", repo, rootpath]) != 0:
    print "Unable to clone repository at %s" % repo
    sys.exit(1)

if opts.branch:
    if subprocess.call(["git", "checkout", opts.branch], cwd=rootpath) != 0:
        sys.exit(1)
if subprocess.call(["git", "remote", "add", "upstream", "git://git.samba.org/samba.git"], cwd=rootpath) != 0:
    sys.exit(1)
if subprocess.call(["git", "fetch", "upstream"], cwd=rootpath) != 0:
    sys.exit(1)
if subprocess.call(["git", "rebase", "upstream/master"], cwd=rootpath) != 0:
    sys.exit(1)

if opts.daemon:
    pid = os.fork()
    if pid == 0: # Parent
        os.setsid()
        pid = os.fork()
        if pid != 0: # Actual daemon
            os._exit(0)
    else: # Grandparent
        os._exit(0)

    import resource      # Resource usage information.
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if maxfd == resource.RLIM_INFINITY:
        maxfd = 1024 # Rough guess at maximum number of open file descriptors.
    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except OSError:
            pass
    os.open(os.devnull, os.O_RDWR)
    os.dup2(0, 1)
    os.dup2(0, 2)

if opts.mail_to:
    (outfd, name) = tempfile.mkstemp()
    outf = os.fdopen(outfd, 'w')
else:
    outf = sys.stdout

def fail(stage):
    if opts.mail_to:
        outf.close()
        f = open(name, 'r')
        msg = MIMEText(f.read())
        f.close()
        msg["Subject"] = "Failure for %s during %s" % (repo, stage)
        msg["To"] = opts.mail_to
        msg["From"] = from_addr
        smtp.connect()
        smtp.sendmail(from_addr, [opts.mail_to], msg.as_string())
        smtp.quit()
    shutil.rmtree(tmpdir)
    sys.exit(1)

s4path = os.path.join(rootpath, "source4")

if subprocess.call(["./autogen.sh"], cwd=s4path, stdout=outf, stderr=outf) != 0:
    fail("Generating configure")
if subprocess.call(["./configure.developer"], cwd=s4path, stdout=outf, stderr=outf) != 0:
    fail("Running configure")
if subprocess.call(["make"], cwd=s4path, stderr=outf, stdout=outf) != 0:
    fail("Building")
if subprocess.call(["make", "check"], cwd=s4path, stderr=outf, stdout=outf) != 0:
    fail("Running testsuite")
if not opts.dry_run:
    if subprocess.call(["git", "push", "git+ssh://git.samba.org/data/git/samba.git", "HEAD:master"], cwd=rootpath, stderr=outf, stdout=outf) != 0:
        fail("Pushing to master")
shutil.rmtree(tmpdir)

if opts.mail_to:
    outf.close()
    f = open(name, 'r')
    msg = MIMEText(f.read())
    f.close()
    msg["Subject"] = "Success landing %s" % repo
    msg["To"] = opts.mail_to
    msg["From"] = from_addr
    smtp.connect()
    smtp.sendmail(from_addr, [opts.mail_to], msg.as_string())
    smtp.quit()
