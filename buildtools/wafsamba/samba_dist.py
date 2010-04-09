# customised version of 'waf dist' for Samba tools
# uses git ls-files to get file lists

import Utils, os, sys, tarfile, stat, Scripting, Logs
from samba_utils import *

dist_dirs = None

def add_tarfile(tar, fname, abspath):
    '''add a file to the tarball'''
    try:
        tinfo = tar.gettarinfo(name=abspath, arcname=fname)
    except OSError:
        Logs.error('Unable to find file %s - missing from git checkout?' % abspath)
        sys.exit(1)
    tinfo.uid   = 0
    tinfo.gid   = 0
    tinfo.uname = 'root'
    tinfo.gname = 'root'
    fh = open(abspath)
    tar.addfile(tinfo, fileobj=fh)
    fh.close()


def dist(appname='',version=''):
    if not isinstance(appname, str) or not appname:
        # this copes with a mismatch in the calling arguments for dist()
        appname = Utils.g_module.APPNAME
        version = Utils.g_module.VERSION
    if not version:
        version = Utils.g_module.VERSION

    srcdir = os.path.normpath(os.path.join(os.path.dirname(Utils.g_module.root_path), Utils.g_module.srcdir))

    if not dist_dirs:
        print('You must use samba_dist.DIST_DIRS() to set which directories to package')
        sys.exit(1)

    dist_base = '%s-%s' % (appname, version)
    dist_name = '%s.tar.gz' % (dist_base)

    tar = tarfile.open(dist_name, 'w:gz')

    for dir in dist_dirs.split():
        if dir.find(':') != -1:
            destdir=dir.split(':')[1]
            dir=dir.split(':')[0]
        else:
            destdir = '.'
        absdir = os.path.join(srcdir, dir)
        git_cmd = [ 'git', 'ls-files', '--full-name', absdir ]
        try:
            files = Utils.cmd_output(git_cmd).split()
        except:
            print('git command failed: %s' % ' '.join(git_cmd))
            sys.exit(1)
        for f in files:
            abspath = os.path.join(srcdir, f)
            if dir != '.':
                f = f[len(dir)+1:]
            if destdir != '.':
                f = destdir + '/' + f
            fname = dist_base + '/' + f
            add_tarfile(tar, fname, abspath)

    tar.close()

    print('Created %s' % dist_name)
    return dist_name


@conf
def DIST_DIRS(dirs):
    '''set the directories to package, relative to top srcdir'''
    global dist_dirs
    if not dist_dirs:
        dist_dirs = dirs

Scripting.dist = dist
