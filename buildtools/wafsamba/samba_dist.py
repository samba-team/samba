# customised version of 'waf dist' for Samba tools
# uses git ls-files to get file lists

import Utils, os, sys, tarfile, stat, Scripting
from samba_utils import *

def add_tarfile(tar, fname, abspath):
    '''add a file to the tarball'''
    tinfo = tar.gettarinfo(name=abspath, arcname=fname)
    tinfo.uid   = 0
    tinfo.gid   = 0
    tinfo.uname = 'root'
    tinfo.gname = 'root'
    fh = open(abspath)
    tar.addfile(tinfo, fileobj=fh)
    fh.close()


def dist():

    appname = Utils.g_module.APPNAME
    version = Utils.g_module.VERSION

    env = LOAD_ENVIRONMENT()
    srcdir = os.path.normpath(os.path.join(os.path.dirname(Utils.g_module.root_path), Utils.g_module.srcdir))

    if not env.DIST_DIRS:
        print('You must use conf.DIST_DIRS() to set which directories to package')
        sys.exit(1)

    if not env.GIT:
        print('You need git installed to run waf dist')
        sys.exit(1)

    dist_base = '%s-%s' % (appname, version)
    dist_name = '%s.tar.gz' % (dist_base)

    tar = tarfile.open(dist_name, 'w:gz')

    for dir in env.DIST_DIRS.split():
        if dir.find(':') != -1:
            destdir=dir.split(':')[1]
            dir=dir.split(':')[0]
        else:
            destdir = '.'
        absdir = os.path.join(srcdir, dir)
        git_cmd = [ env.GIT, 'ls-files', '--full-name', absdir ]
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


@conf
def DIST_DIRS(conf, dirs):
    '''set the directories to package, relative to top srcdir'''
    if not conf.env.DIST_DIRS:
        conf.env.DIST_DIRS = dirs

Scripting.dist = dist
