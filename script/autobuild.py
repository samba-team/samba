#!/usr/bin/env python
# run tests on all Samba subprojects and push to a git tree on success
# Copyright Andrew Tridgell 2010
# released under GNU GPL v3 or later

from subprocess import call, check_call,Popen, PIPE
import os, tarfile, sys, time
from optparse import OptionParser
import smtplib
from email.mime.text import MIMEText
from distutils.sysconfig import get_python_lib

# This speeds up testing remarkably.
os.environ['TDB_NO_FSYNC'] = '1'

cleanup_list = []

builddirs = {
    "ctdb"    : "ctdb",
    "samba"  : ".",
    "samba-ctdb" : ".",
    "samba-libs"  : ".",
    "ldb"     : "lib/ldb",
    "tdb"     : "lib/tdb",
    "ntdb"    : "lib/ntdb",
    "talloc"  : "lib/talloc",
    "replace" : "lib/replace",
    "tevent"  : "lib/tevent",
    "pidl"    : "pidl",
    "pass"    : ".",
    "fail"    : ".",
    "retry"   : "."
    }

defaulttasks = [ "ctdb", "samba", "samba-ctdb", "samba-libs", "ldb", "tdb", "ntdb", "talloc", "replace", "tevent", "pidl" ]

tasks = {
    "ctdb" : [ ("random-sleep", "../script/random-sleep.sh 60 600", "text/plain"),
               ("configure", "./configure ${PREFIX}", "text/plain"),
               ("make", "make all", "text/plain"),
               ("install", "make install", "text/plain"),
               ("test", "make autotest", "text/plain"),
               ("check-clean-tree", "../script/clean-source-tree.sh", "text/plain"),
               ("clean", "make clean", "text/plain") ],

    # We have 'test' before 'install' because, 'test' should work without 'install'
    "samba" : [ ("configure", "./configure.developer ${PREFIX} --with-selftest-prefix=./bin/ab", "text/plain"),
                ("make", "make -j", "text/plain"),
                ("test", "make test FAIL_IMMEDIATELY=1", "text/plain"),
                ("install", "make install", "text/plain"),
                ("check-clean-tree", "script/clean-source-tree.sh", "text/plain"),
                ("clean", "make clean", "text/plain") ],

    "samba-ctdb" : [ ("random-sleep", "script/random-sleep.sh 60 600", "text/plain"),

                     # make sure we have tdb around:
                     ("tdb-configure", "cd lib/tdb && PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                     ("tdb-make", "cd lib/tdb && make", "text/plain"),
                     ("tdb-install", "cd lib/tdb && make install", "text/plain"),


                     # build samba with cluster support against this ctdb:
                     ("samba-configure", "PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=${PREFIX_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH} ./configure.developer ${PREFIX} --with-selftest-prefix=./bin/ab --with-cluster-support --bundled-libraries=!tdb", "text/plain"),
                     ("samba-make", "make", "text/plain"),
                     ("samba-check", "./bin/smbd -b | grep CLUSTER_SUPPORT", "text/plain"),
                     ("samba-install", "make install", "text/plain"),
                     ("ctdb-check", "test -e ${PREFIX_DIR}/sbin/ctdbd", "text/plain"),

                     # clean up:
                     ("check-clean-tree", "script/clean-source-tree.sh", "text/plain"),
                     ("clean", "make clean", "text/plain"),
                     ("ctdb-clean", "cd ./ctdb && make clean", "text/plain") ],

    "samba-libs" : [
                      ("random-sleep", "script/random-sleep.sh 60 600", "text/plain"),
                      ("talloc-configure", "cd lib/talloc && PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                      ("talloc-make", "cd lib/talloc && make", "text/plain"),
                      ("talloc-install", "cd lib/talloc && make install", "text/plain"),

                      ("tdb-configure", "cd lib/tdb && PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                      ("tdb-make", "cd lib/tdb && make", "text/plain"),
                      ("tdb-install", "cd lib/tdb && make install", "text/plain"),

                      ("ntdb-configure", "cd lib/ntdb && PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                      ("ntdb-make", "cd lib/ntdb && make", "text/plain"),
                      ("ntdb-install", "cd lib/ntdb && make install", "text/plain"),

                      ("tevent-configure", "cd lib/tevent && PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                      ("tevent-make", "cd lib/tevent && make", "text/plain"),
                      ("tevent-install", "cd lib/tevent && make install", "text/plain"),

                      ("ldb-configure", "cd lib/ldb && PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=NONE --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                      ("ldb-make", "cd lib/ldb && make", "text/plain"),
                      ("ldb-install", "cd lib/ldb && make install", "text/plain"),

                      ("configure", "PYTHONPATH=${PYTHON_PREFIX}/site-packages:$PYTHONPATH PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX_DIR}/lib/pkgconfig ./configure --bundled-libraries=!talloc,!tdb,!pytdb,!ntdb,!pyntdb,!ldb,!pyldb,!tevent,!pytevent --abi-check --enable-debug -C ${PREFIX}", "text/plain"),
                      ("make", "make", "text/plain"),
                      ("install", "make install", "text/plain"),
                      ("dist", "make dist", "text/plain")],

    "ldb" : [
              ("random-sleep", "../../script/random-sleep.sh 60 600", "text/plain"),
              ("configure", "./configure --enable-developer -C ${PREFIX}", "text/plain"),
              ("make", "make", "text/plain"),
              ("install", "make install", "text/plain"),
              ("test", "make test", "text/plain"),
              ("check-clean-tree", "../../script/clean-source-tree.sh", "text/plain"),
              ("distcheck", "make distcheck", "text/plain"),
              ("clean", "make clean", "text/plain") ],

    "tdb" : [
              ("random-sleep", "../../script/random-sleep.sh 60 600", "text/plain"),
              ("configure", "./configure --enable-developer -C ${PREFIX}", "text/plain"),
              ("make", "make", "text/plain"),
              ("install", "make install", "text/plain"),
              ("test", "make test", "text/plain"),
              ("check-clean-tree", "../../script/clean-source-tree.sh", "text/plain"),
              ("distcheck", "make distcheck", "text/plain"),
              ("clean", "make clean", "text/plain") ],

    "ntdb" : [
               ("random-sleep", "../../script/random-sleep.sh 60 600", "text/plain"),
               ("configure", "./configure --enable-developer -C ${PREFIX}", "text/plain"),
               ("make", "make", "text/plain"),
               ("install", "make install", "text/plain"),
               ("test", "make test", "text/plain"),
               ("check-clean-tree", "../../script/clean-source-tree.sh", "text/plain"),
               ("distcheck", "make distcheck", "text/plain"),
               ("clean", "make clean", "text/plain") ],

    "talloc" : [
                 ("random-sleep", "../../script/random-sleep.sh 60 600", "text/plain"),
                 ("configure", "./configure --enable-developer -C ${PREFIX}", "text/plain"),
                 ("make", "make", "text/plain"),
                 ("install", "make install", "text/plain"),
                 ("test", "make test", "text/plain"),
                 ("check-clean-tree", "../../script/clean-source-tree.sh", "text/plain"),
                 ("distcheck", "make distcheck", "text/plain"),
                 ("clean", "make clean", "text/plain") ],

    "replace" : [
                  ("random-sleep", "../../script/random-sleep.sh 60 600", "text/plain"),
                  ("configure", "./configure --enable-developer -C ${PREFIX}", "text/plain"),
                  ("make", "make", "text/plain"),
                  ("install", "make install", "text/plain"),
                  ("test", "make test", "text/plain"),
                  ("check-clean-tree", "../../script/clean-source-tree.sh", "text/plain"),
                  ("distcheck", "make distcheck", "text/plain"),
                  ("clean", "make clean", "text/plain") ],

    "tevent" : [
                 ("random-sleep", "../../script/random-sleep.sh 60 600", "text/plain"),
                 ("configure", "./configure --enable-developer -C ${PREFIX}", "text/plain"),
                 ("make", "make", "text/plain"),
                 ("install", "make install", "text/plain"),
                 ("test", "make test", "text/plain"),
                 ("check-clean-tree", "../../script/clean-source-tree.sh", "text/plain"),
                 ("distcheck", "make distcheck", "text/plain"),
                 ("clean", "make clean", "text/plain") ],

    "pidl" : [
               ("random-sleep", "../script/random-sleep.sh 60 600", "text/plain"),
               ("configure", "perl Makefile.PL PREFIX=${PREFIX_DIR}", "text/plain"),
               ("touch", "touch *.yp", "text/plain"),
               ("make", "make", "text/plain"),
               ("test", "make test", "text/plain"),
               ("install", "make install", "text/plain"),
               ("check-clean-tree", "../script/clean-source-tree.sh", "text/plain"),
               ("clean", "make clean", "text/plain") ],

    # these are useful for debugging autobuild
    'pass' : [ ("pass", 'echo passing && /bin/true', "text/plain") ],
    'fail' : [ ("fail", 'echo failing && /bin/false', "text/plain") ]
}

def run_cmd(cmd, dir=".", show=None, output=False, checkfail=True):
    if show is None:
        show = options.verbose
    if show:
        print("Running: '%s' in '%s'" % (cmd, dir))
    if output:
        return Popen([cmd], shell=True, stdout=PIPE, cwd=dir).communicate()[0]
    elif checkfail:
        return check_call(cmd, shell=True, cwd=dir)
    else:
        return call(cmd, shell=True, cwd=dir)


class builder(object):
    '''handle build of one directory'''

    def __init__(self, name, sequence):
        self.name = name
        self.dir = builddirs[name]

        self.tag = self.name.replace('/', '_')
        self.sequence = sequence
        self.next = 0
        self.stdout_path = "%s/%s.stdout" % (gitroot, self.tag)
        self.stderr_path = "%s/%s.stderr" % (gitroot, self.tag)
        if options.verbose:
            print("stdout for %s in %s" % (self.name, self.stdout_path))
            print("stderr for %s in %s" % (self.name, self.stderr_path))
        run_cmd("rm -f %s %s" % (self.stdout_path, self.stderr_path))
        self.stdout = open(self.stdout_path, 'w')
        self.stderr = open(self.stderr_path, 'w')
        self.stdin  = open("/dev/null", 'r')
        self.sdir = "%s/%s" % (testbase, self.tag)
        self.prefix = "%s/prefix/%s" % (testbase, self.tag)
        run_cmd("rm -rf %s" % self.sdir)
        cleanup_list.append(self.sdir)
        cleanup_list.append(self.prefix)
        os.makedirs(self.sdir)
        run_cmd("rm -rf %s" % self.sdir)
        run_cmd("git clone --shared %s %s" % (test_master, self.sdir), dir=test_master, show=True)
        self.start_next()

    def start_next(self):
        if self.next == len(self.sequence):
            print '%s: Completed OK' % self.name
            self.done = True
            return
        (self.stage, self.cmd, self.output_mime_type) = self.sequence[self.next]
        self.cmd = self.cmd.replace("${PYTHON_PREFIX}", get_python_lib(standard_lib=1, prefix=self.prefix))
        self.cmd = self.cmd.replace("${PREFIX}", "--prefix=%s" % self.prefix)
        self.cmd = self.cmd.replace("${PREFIX_DIR}", "%s" % self.prefix)
#        if self.output_mime_type == "text/x-subunit":
#            self.cmd += " | %s --immediate" % (os.path.join(os.path.dirname(__file__), "selftest/format-subunit"))
        print '%s: [%s] Running %s' % (self.name, self.stage, self.cmd)
        cwd = os.getcwd()
        os.chdir("%s/%s" % (self.sdir, self.dir))
        self.proc = Popen(self.cmd, shell=True,
                          stdout=self.stdout, stderr=self.stderr, stdin=self.stdin)
        os.chdir(cwd)
        self.next += 1


class buildlist(object):
    '''handle build of multiple directories'''

    def __init__(self, tasklist, tasknames, rebase_url, rebase_branch="master"):
        global tasks
        self.tlist = []
        self.tail_proc = None
        self.retry = None
        if tasknames == []:
            tasknames = defaulttasks
        for n in tasknames:
            b = builder(n, tasks[n])
            self.tlist.append(b)
        if options.retry:
            rebase_remote = "rebaseon"
            retry_task = [ ("retry",
                            '''set -e
                            git remote add -t %s %s %s
                            git fetch %s
                            while :; do
                              sleep 60
                              git describe %s/%s > old_remote_branch.desc
                              git fetch %s
                              git describe %s/%s > remote_branch.desc
                              diff old_remote_branch.desc remote_branch.desc
                            done
                           ''' % (
                               rebase_branch, rebase_remote, rebase_url,
                               rebase_remote,
                               rebase_remote, rebase_branch,
                               rebase_remote,
                               rebase_remote, rebase_branch
                           ),
                           "test/plain" ) ]

            self.retry = builder('retry', retry_task)
            self.need_retry = False

    def kill_kids(self):
        if self.tail_proc is not None:
            self.tail_proc.terminate()
            self.tail_proc.wait()
            self.tail_proc = None
        if self.retry is not None:
            self.retry.proc.terminate()
            self.retry.proc.wait()
            self.retry = None
        for b in self.tlist:
            if b.proc is not None:
                run_cmd("killbysubdir %s > /dev/null 2>&1" % b.sdir, checkfail=False)
                b.proc.terminate()
                b.proc.wait()
                b.proc = None

    def wait_one(self):
        while True:
            none_running = True
            for b in self.tlist:
                if b.proc is None:
                    continue
                none_running = False
                b.status = b.proc.poll()
                if b.status is None:
                    continue
                b.proc = None
                return b
            if options.retry:
                ret = self.retry.proc.poll()
                if ret is not None:
                    self.need_retry = True
                    self.retry = None
                    return None
            if none_running:
                return None
            time.sleep(0.1)

    def run(self):
        while True:
            b = self.wait_one()
            if options.retry and self.need_retry:
                self.kill_kids()
                print("retry needed")
                return (0, None, None, None, "retry")
            if b is None:
                break
            if os.WIFSIGNALED(b.status) or os.WEXITSTATUS(b.status) != 0:
                self.kill_kids()
                return (b.status, b.name, b.stage, b.tag, "%s: [%s] failed '%s' with status %d" % (b.name, b.stage, b.cmd, b.status))
            b.start_next()
        self.kill_kids()
        return (0, None, None, None, "All OK")

    def tarlogs(self, fname):
        tar = tarfile.open(fname, "w:gz")
        for b in self.tlist:
            tar.add(b.stdout_path, arcname="%s.stdout" % b.tag)
            tar.add(b.stderr_path, arcname="%s.stderr" % b.tag)
        if os.path.exists("autobuild.log"):
            tar.add("autobuild.log")
        tar.close()

    def remove_logs(self):
        for b in self.tlist:
            os.unlink(b.stdout_path)
            os.unlink(b.stderr_path)

    def start_tail(self):
        cwd = os.getcwd()
        cmd = "tail -f *.stdout *.stderr"
        os.chdir(gitroot)
        self.tail_proc = Popen(cmd, shell=True)
        os.chdir(cwd)


def cleanup():
    if options.nocleanup:
        return
    print("Cleaning up ....")
    for d in cleanup_list:
        run_cmd("rm -rf %s" % d)


def find_git_root():
    '''get to the top of the git repo'''
    p=os.getcwd()
    while p != '/':
        if os.path.isdir(os.path.join(p, ".git")):
            return p
        p = os.path.abspath(os.path.join(p, '..'))
    return None


def daemonize(logfile):
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
    os.open(logfile, os.O_RDWR | os.O_CREAT)
    os.dup2(0, 1)
    os.dup2(0, 2)

def write_pidfile(fname):
    '''write a pid file, cleanup on exit'''
    f = open(fname, mode='w')
    f.write("%u\n" % os.getpid())
    f.close()


def rebase_tree(rebase_url, rebase_branch = "master"):
    rebase_remote = "rebaseon"
    print("Rebasing on %s" % rebase_url)
    run_cmd("git describe HEAD", show=True, dir=test_master)
    run_cmd("git remote add -t %s %s %s" %
            (rebase_branch, rebase_remote, rebase_url),
            show=True, dir=test_master)
    run_cmd("git fetch %s" % rebase_remote, show=True, dir=test_master)
    if options.fix_whitespace:
        run_cmd("git rebase --force-rebase --whitespace=fix %s/%s" %
                (rebase_remote, rebase_branch),
                show=True, dir=test_master)
    else:
        run_cmd("git rebase --force-rebase %s/%s" %
                (rebase_remote, rebase_branch),
                show=True, dir=test_master)
    diff = run_cmd("git --no-pager diff HEAD %s/%s" %
                   (rebase_remote, rebase_branch),
                   dir=test_master, output=True)
    if diff == '':
        print("No differences between HEAD and %s/%s - exiting" %
              (rebase_remote, rebase_branch))
        sys.exit(0)
    run_cmd("git describe %s/%s" %
            (rebase_remote, rebase_branch),
            show=True, dir=test_master)
    run_cmd("git describe HEAD", show=True, dir=test_master)
    run_cmd("git --no-pager diff --stat HEAD %s/%s" %
            (rebase_remote, rebase_branch),
            show=True, dir=test_master)

def push_to(push_url, push_branch = "master"):
    push_remote = "pushto"
    print("Pushing to %s" % push_url)
    if options.mark:
        run_cmd("git config --replace-all core.editor script/commit_mark.sh", dir=test_master)
        run_cmd("git commit --amend -c HEAD", dir=test_master)
        # the notes method doesn't work yet, as metze hasn't allowed refs/notes/* in master
        # run_cmd("EDITOR=script/commit_mark.sh git notes edit HEAD", dir=test_master)
    run_cmd("git remote add -t %s %s %s" %
            (push_branch, push_remote, push_url),
            show=True, dir=test_master)
    run_cmd("git push %s +HEAD:%s" %
            (push_remote, push_branch),
            show=True, dir=test_master)

def_testbase = os.getenv("AUTOBUILD_TESTBASE", "/memdisk/%s" % os.getenv('USER'))

gitroot = find_git_root()
if gitroot is None:
    raise Exception("Failed to find git root")

parser = OptionParser()
parser.add_option("", "--tail", help="show output while running", default=False, action="store_true")
parser.add_option("", "--keeplogs", help="keep logs", default=False, action="store_true")
parser.add_option("", "--nocleanup", help="don't remove test tree", default=False, action="store_true")
parser.add_option("", "--testbase", help="base directory to run tests in (default %s)" % def_testbase,
                  default=def_testbase)
parser.add_option("", "--passcmd", help="command to run on success", default=None)
parser.add_option("", "--verbose", help="show all commands as they are run",
                  default=False, action="store_true")
parser.add_option("", "--rebase", help="rebase on the given tree before testing",
                  default=None, type='str')
parser.add_option("", "--pushto", help="push to a git url on success",
                  default=None, type='str')
parser.add_option("", "--mark", help="add a Tested-By signoff before pushing",
                  default=False, action="store_true")
parser.add_option("", "--fix-whitespace", help="fix whitespace on rebase",
                  default=False, action="store_true")
parser.add_option("", "--retry", help="automatically retry if master changes",
                  default=False, action="store_true")
parser.add_option("", "--email", help="send email to the given address on failure",
                  type='str', default=None)
parser.add_option("", "--always-email", help="always send email, even on success",
                  action="store_true")
parser.add_option("", "--daemon", help="daemonize after initial setup",
                  action="store_true")
parser.add_option("", "--branch", help="the branch to work on (default=master)",
                  default="master", type='str')
parser.add_option("", "--log-base", help="location where the logs can be found (default=cwd)",
                  default=gitroot, type='str')

def email_failure(status, failed_task, failed_stage, failed_tag, errstr, log_base=None):
    '''send an email to options.email about the failure'''
    user = os.getenv("USER")
    if log_base is None:
        log_base = gitroot
    text = '''
Dear Developer,

Your autobuild failed when trying to test %s with the following error:
   %s

the autobuild has been abandoned. Please fix the error and resubmit.

A summary of the autobuild process is here:

  %s/autobuild.log
''' % (failed_task, errstr, log_base)
    
    if failed_task != 'rebase':
        text += '''
You can see logs of the failed task here:

  %s/%s.stdout
  %s/%s.stderr

or you can get full logs of all tasks in this job here:

  %s/logs.tar.gz

The top commit for the tree that was built was:

%s

''' % (log_base, failed_tag, log_base, failed_tag, log_base, top_commit_msg)
    msg = MIMEText(text)
    msg['Subject'] = 'autobuild failure for task %s during %s' % (failed_task, failed_stage)
    msg['From'] = 'autobuild@samba.org'
    msg['To'] = options.email

    s = smtplib.SMTP()
    s.connect()
    s.sendmail(msg['From'], [msg['To']], msg.as_string())
    s.quit()

def email_success(log_base=None):
    '''send an email to options.email about a successful build'''
    user = os.getenv("USER")
    if log_base is None:
        log_base = gitroot
    text = '''
Dear Developer,

Your autobuild has succeeded.

'''

    if options.keeplogs:
        text += '''

you can get full logs of all tasks in this job here:

  %s/logs.tar.gz

''' % log_base

    text += '''
The top commit for the tree that was built was:

%s
''' % top_commit_msg

    msg = MIMEText(text)
    msg['Subject'] = 'autobuild success'
    msg['From'] = 'autobuild@samba.org'
    msg['To'] = options.email

    s = smtplib.SMTP()
    s.connect()
    s.sendmail(msg['From'], [msg['To']], msg.as_string())
    s.quit()


(options, args) = parser.parse_args()

if options.retry:
    if options.rebase is None:
        raise Exception('You can only use --retry if you also rebase')

testbase = "%s/b%u" % (options.testbase, os.getpid())
test_master = "%s/master" % testbase

# get the top commit message, for emails
top_commit_msg = run_cmd("git log -1", dir=gitroot, output=True)

try:
    os.makedirs(testbase)
except Exception, reason:
    raise Exception("Unable to create %s : %s" % (testbase, reason))
cleanup_list.append(testbase)

if options.daemon:
    logfile = os.path.join(testbase, "log")
    print "Forking into the background, writing progress to %s" % logfile
    daemonize(logfile)

write_pidfile(gitroot + "/autobuild.pid")

while True:
    try:
        run_cmd("rm -rf %s" % test_master)
        cleanup_list.append(test_master)
        run_cmd("git clone --shared %s %s" % (gitroot, test_master), show=True, dir=gitroot)
    except Exception:
        cleanup()
        raise

    try:
        try:
            if options.rebase is not None:
                rebase_tree(options.rebase, rebase_branch=options.branch)
        except Exception:
            cleanup_list.append(gitroot + "/autobuild.pid")
            cleanup()
            email_failure(-1, 'rebase', 'rebase', 'rebase',
                          'rebase on %s failed' % options.branch,
                          log_base=options.log_base)
            sys.exit(1)
        blist = buildlist(tasks, args, options.rebase, rebase_branch=options.branch)
        if options.tail:
            blist.start_tail()
        (status, failed_task, failed_stage, failed_tag, errstr) = blist.run()
        if status != 0 or errstr != "retry":
            break
        cleanup()
    except Exception:
        cleanup()
        raise

cleanup_list.append(gitroot + "/autobuild.pid")

blist.kill_kids()
if options.tail:
    print("waiting for tail to flush")
    time.sleep(1)

if status == 0:
    print errstr
    if options.passcmd is not None:
        print("Running passcmd: %s" % options.passcmd)
        run_cmd(options.passcmd, dir=test_master)
    if options.pushto is not None:
        push_to(options.pushto, push_branch=options.branch)
    if options.keeplogs:
        blist.tarlogs("logs.tar.gz")
        print("Logs in logs.tar.gz")
    if options.always_email:
        email_success(log_base=options.log_base)
    blist.remove_logs()
    cleanup()
    print(errstr)
    sys.exit(0)

# something failed, gather a tar of the logs
blist.tarlogs("logs.tar.gz")

if options.email is not None:
    email_failure(status, failed_task, failed_stage, failed_tag, errstr, log_base=options.log_base)

cleanup()
print(errstr)
print("Logs in logs.tar.gz")
sys.exit(status)
