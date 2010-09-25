#!/usr/bin/env python
# run tests on all Samba subprojects and push to a git tree on success
# Copyright Andrew Tridgell 2010
# released under GNU GPL v3 or later

from subprocess import Popen, PIPE
import os, signal, tarfile, sys, time
from optparse import OptionParser


cleanup_list = []

tasks = {
    "source3" : [ "./autogen.sh",
                  "./configure.developer ${PREFIX}",
                  "make basics",
                  "make -j",
                  "make test" ],

    "source4" : [ "./autogen.sh",
                  "./configure.developer ${PREFIX}",
                  "make -j",
                  "make test" ],

    "source4/lib/ldb" : [ "./autogen-waf.sh",
                          "./configure --enable-developer -C ${PREFIX}",
                          "make -j",
                          "make test" ],

    "lib/tdb" : [ "./autogen-waf.sh",
                  "./configure --enable-developer -C ${PREFIX}",
                  "make -j",
                  "make test" ],

    "lib/talloc" : [ "./autogen-waf.sh",
                     "./configure --enable-developer -C ${PREFIX}",
                     "make -j",
                     "make test" ],

    "lib/replace" : [ "./autogen-waf.sh",
                      "./configure --enable-developer -C ${PREFIX}",
                      "make -j",
                      "make test" ],

    "lib/tevent" : [ "./autogen-waf.sh",
                     "./configure --enable-developer -C ${PREFIX}",
                     "make -j",
                     "make test" ],
}

def run_cmd(cmd, dir=".", show=None):
    cwd = os.getcwd()
    os.chdir(dir)
    if show is None:
        show = options.verbose
    if show:
        print("Running: '%s' in '%s'" % (cmd, dir))
    ret = os.system(cmd)
    os.chdir(cwd)
    if ret != 0:
        raise Exception("FAILED %s: %d" % (cmd, ret))

class builder:
    '''handle build of one directory'''
    def __init__(self, name, sequence):
        self.name = name
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
        os.chdir("%s/%s" % (self.sdir, self.name))
        self.proc = Popen(self.cmd, shell=True,
                          stdout=self.stdout, stderr=self.stderr, stdin=self.stdin)
        os.chdir(cwd)
        self.next += 1


class buildlist:
    '''handle build of multiple directories'''
    def __init__(self, tasklist, tasknames):
        self.tlist = []
        self.tail_proc = None
        if tasknames == []:
            tasknames = tasklist
        for n in tasknames:
            b = builder(n, tasks[n])
            self.tlist.append(b)

    def kill_kids(self):
        for b in self.tlist:
            if b.proc is not None:
                b.proc.terminate()
                b.proc.wait()
                b.proc = None
        if self.tail_proc is not None:
            self.tail_proc.terminate()
            self.tail_proc.wait()
            self.tail_proc = None

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
            if none_running:
                return None
            time.sleep(0.1)

    def run(self):
        while True:
            b = self.wait_one()
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
    run_cmd("git rebase master/master", show=True, dir=test_master)

def_testbase = os.getenv("AUTOBUILD_TESTBASE", "/memdisk/%s" % os.getenv('USER'))
def_passcmd  = os.getenv("AUTOBUILD_PASSCMD",
                         "git push %s/master-passed +HEAD:master" % os.getenv("HOME"))

parser = OptionParser()
parser.add_option("", "--tail", help="show output while running", default=False, action="store_true")
parser.add_option("", "--keeplogs", help="keep logs", default=False, action="store_true")
parser.add_option("", "--testbase", help="base directory to run tests in (default %s)" % def_testbase,
                  default=def_testbase)
parser.add_option("", "--passcmd", help="command to run on success (default %s)" % def_passcmd,
                  default=def_passcmd)
parser.add_option("", "--verbose", help="show all commands as they are run",
                  default=False, action="store_true")
parser.add_option("", "--rebase", help="rebase on the given tree before testing",
                  default=None, type='str')


(options, args) = parser.parse_args()

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
    blist = buildlist(tasks, args)
    if options.tail:
        blist.start_tail()
    (status, errstr) = blist.run()
except:
    cleanup()
    raise

blist.kill_kids()
if options.tail:
    print("waiting for tail to flush")
    time.sleep(1)

if status == 0:
    print errstr
    print("Running passcmd: %s" % options.passcmd)
    run_cmd(options.passcmd, dir=test_master)
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
