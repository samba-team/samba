#!/usr/bin/env python
# run tests on all Samba subprojects and push to a git tree on success
# Copyright Andrew Tridgell 2010
# released under GNU GPL v3 or later

from subprocess import Popen, PIPE
import os, signal, tarfile, sys, time
from optparse import OptionParser


samba_master = os.getenv('SAMBA_MASTER', 'git://git.samba.org/samba.git')
samba_master_ssh = os.getenv('SAMBA_MASTER_SSH', 'git+ssh://git.samba.org/data/git/samba.git')

cleanup_list = []

os.putenv('CC', "ccache gcc")

tasks = {
    "source3" : [ "./autogen.sh",
                  "./configure.developer ${PREFIX}",
                  "make basics",
                  "make -j 4 everything", # don't use too many processes
                  "make install",
                  "TDB_NO_FSYNC=1 make test FAIL_IMMEDIATELY=1" ],

    "source4" : [ "./autogen.sh",
                  "./configure.developer ${PREFIX}",
                  "make -j",
                  "make install",
                  "TDB_NO_FSYNC=1 make test FAIL_IMMEDIATELY=1" ],

    "source4/lib/ldb" : [ "./autogen-waf.sh",
                          "./configure --enable-developer -C ${PREFIX}",
                          "make -j",
                          "make install",
                          "make test" ],

    "lib/tdb" : [ "./autogen-waf.sh",
                  "./configure --enable-developer -C ${PREFIX}",
                  "make -j",
                  "make install",
                  "make test" ],

    "lib/talloc" : [ "./autogen-waf.sh",
                     "./configure --enable-developer -C ${PREFIX}",
                     "make -j",
                     "make install",
                     "make test" ],

    "lib/replace" : [ "./autogen-waf.sh",
                      "./configure --enable-developer -C ${PREFIX}",
                      "make -j",
                      "make install",
                      "make test" ],

    "lib/tevent" : [ "./autogen-waf.sh",
                     "./configure --enable-developer -C ${PREFIX}",
                     "make -j",
                     "make install",
                     "make test" ],
}

retry_task = [ '''set -e
                git remote add -t master master %s
                git fetch master
                while :; do
                  sleep 60
                  git describe master/master > old_master.desc
                  git fetch master
                  git describe master/master > master.desc
                  diff old_master.desc master.desc
                done
               ''' % samba_master]

def run_cmd(cmd, dir=".", show=None, output=False, checkfail=True):
    cwd = os.getcwd()
    os.chdir(dir)
    if show is None:
        show = options.verbose
    if show:
        print("Running: '%s' in '%s'" % (cmd, dir))
    if output:
        ret = Popen([cmd], shell=True, stdout=PIPE).communicate()[0]
        os.chdir(cwd)
        return ret
    ret = os.system(cmd)
    os.chdir(cwd)
    if checkfail and ret != 0:
        raise Exception("FAILED %s: %d" % (cmd, ret))
    return ret

class builder:
    '''handle build of one directory'''
    def __init__(self, name, sequence):
        self.name = name

        if name in ['pass', 'fail', 'retry']:
            self.dir = "."
        else:
            self.dir = self.name

        self.tag = self.name.replace('/', '_')
        self.sequence = sequence
        self.next = 0
        self.stdout_path = "%s/%s.stdout" % (testbase, self.tag)
        self.stderr_path = "%s/%s.stderr" % (testbase, self.tag)
        cleanup_list.append(self.stdout_path)
        cleanup_list.append(self.stderr_path)
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
        run_cmd("git clone --shared %s %s" % (gitroot, self.sdir))
        self.start_next()

    def start_next(self):
        if self.next == len(self.sequence):
            print '%s: Completed OK' % self.name
            self.done = True
            return
        self.cmd = self.sequence[self.next].replace("${PREFIX}", "--prefix=%s" % self.prefix)
        print '%s: Running %s' % (self.name, self.cmd)
        cwd = os.getcwd()
        os.chdir("%s/%s" % (self.sdir, self.dir))
        self.proc = Popen(self.cmd, shell=True,
                          stdout=self.stdout, stderr=self.stderr, stdin=self.stdin)
        os.chdir(cwd)
        self.next += 1


class buildlist:
    '''handle build of multiple directories'''
    def __init__(self, tasklist, tasknames):
        global tasks
        self.tlist = []
        self.tail_proc = None
        self.retry = None
        if tasknames == ['pass']:
            tasks = { 'pass' : [ '/bin/true' ]}
        if tasknames == ['fail']:
            tasks = { 'fail' : [ '/bin/false' ]}
        if tasknames == []:
            tasknames = tasklist
        for n in tasknames:
            b = builder(n, tasks[n])
            self.tlist.append(b)
        if options.retry:
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
                return (0, "retry")
            if b is None:
                break
            if os.WIFSIGNALED(b.status) or os.WEXITSTATUS(b.status) != 0:
                self.kill_kids()
                return (b.status, "%s: failed '%s' with status %d" % (b.name, b.cmd, b.status))
            b.start_next()
        self.kill_kids()
        return (0, "All OK")

    def tarlogs(self, fname):
        tar = tarfile.open(fname, "w:gz")
        for b in self.tlist:
            tar.add(b.stdout_path, arcname="%s.stdout" % b.tag)
            tar.add(b.stderr_path, arcname="%s.stderr" % b.tag)
        tar.close()

    def remove_logs(self):
        for b in self.tlist:
            os.unlink(b.stdout_path)
            os.unlink(b.stderr_path)

    def start_tail(self):
        cwd = os.getcwd()
        cmd = "tail -f *.stdout *.stderr"
        os.chdir(testbase)
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
    cwd=os.getcwd()
    while os.getcwd() != '/':
        try:
            os.stat(".git")
            ret = os.getcwd()
            os.chdir(cwd)
            return ret
        except:
            os.chdir("..")
            pass
    os.chdir(cwd)
    return None

def rebase_tree(url):
    print("Rebasing on %s" % url)
    run_cmd("git remote add -t master master %s" % url, show=True, dir=test_master)
    run_cmd("git fetch master", show=True, dir=test_master)
    if options.fix_whitespace:
        run_cmd("git rebase --whitespace=fix master/master", show=True, dir=test_master)
    else:
        run_cmd("git rebase master/master", show=True, dir=test_master)
    diff = run_cmd("git --no-pager diff HEAD master/master", dir=test_master, output=True)
    if diff == '':
        print("No differences between HEAD and master/master - exiting")
        sys.exit(0)

def push_to(url):
    print("Pushing to %s" % url)
    if options.mark:
        run_cmd("EDITOR=script/commit_mark.sh git notes edit HEAD", dir=test_master)
    run_cmd("git remote add -t master pushto %s" % url, show=True, dir=test_master)
    run_cmd("git push pushto +HEAD:master", show=True, dir=test_master)

def_testbase = os.getenv("AUTOBUILD_TESTBASE", "/memdisk/%s" % os.getenv('USER'))

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
parser.add_option("", "--rebase-master", help="rebase on %s before testing" % samba_master,
                  default=False, action='store_true')
parser.add_option("", "--pushto", help="push to a git url on success",
                  default=None, type='str')
parser.add_option("", "--push-master", help="push to %s on success" % samba_master_ssh,
                  default=False, action='store_true')
parser.add_option("", "--mark", help="add a Tested-By signoff before pushing",
                  default=False, action="store_true")
parser.add_option("", "--fix-whitespace", help="fix whitespace on rebase",
                  default=False, action="store_true")
parser.add_option("", "--retry", help="automatically retry if master changes",
                  default=False, action="store_true")


(options, args) = parser.parse_args()

if options.retry:
    if not options.rebase_master and options.rebase is None:
        raise Exception('You can only use --retry if you also rebase')

testbase = "%s/build.%u" % (options.testbase, os.getpid())
test_master = "%s/master" % testbase

gitroot = find_git_root()
if gitroot is None:
    raise Exception("Failed to find git root")

try:
    os.makedirs(testbase)
except Exception, reason:
    raise Exception("Unable to create %s : %s" % (testbase, reason))
cleanup_list.append(testbase)

while True:
    try:
        run_cmd("rm -rf %s" % test_master)
        cleanup_list.append(test_master)
        run_cmd("git clone --shared %s %s" % (gitroot, test_master))
    except:
        cleanup()
        raise

    try:
        if options.rebase is not None:
            rebase_tree(options.rebase)
        elif options.rebase_master:
            rebase_tree(samba_master)
        blist = buildlist(tasks, args)
        if options.tail:
            blist.start_tail()
        (status, errstr) = blist.run()
        if status != 0 or errstr != "retry":
            break
        cleanup()
    except:
        cleanup()
        raise

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
        push_to(options.pushto)
    elif options.push_master:
        push_to(samba_master_ssh)
    if options.keeplogs:
        blist.tarlogs("logs.tar.gz")
        print("Logs in logs.tar.gz")
    blist.remove_logs()
    cleanup()
    print(errstr)
    sys.exit(0)

# something failed, gather a tar of the logs
blist.tarlogs("logs.tar.gz")
blist.remove_logs()
cleanup()
print(errstr)
print("Logs in logs.tar.gz")
sys.exit(os.WEXITSTATUS(status))
