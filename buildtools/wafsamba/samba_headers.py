# specialist handling of header files for Samba

import Build, re, Task, TaskGen
from samba_utils import *


def header_install_path(header, header_path):
    '''find the installation path for a header, given a header_path option'''
    if not header_path:
        return ''
    if not isinstance(header_path, list):
        return header_path
    for (p1, dir) in header_path:
        for p2 in TO_LIST(p1):
            if fnmatch.fnmatch(header, p2):
                return dir
    # default to current path
    return ''


re_header = re.compile('#include[ \t]*"([^"]+)"', re.I | re.M)
class header_task(Task.Task):
    """
    The public headers (the one installed on the system) have both
    different paths and contents, so the rename is not enough.

    Intermediate .inst.h files are created because path manipulation
    may be slow. The substitution is thus performed only once.
    """

    name = 'header'
    color = 'PINK'
    vars = ['INCLUDEDIR', 'HEADER_DEPS']

    def run(self):
        txt = self.inputs[0].read(self.env)

        # hard-coded string, but only present in samba4 (I promise, you won't feel a thing)
        txt = txt.replace('#if _SAMBA_BUILD_ == 4', '#if 1\n')

        # use a regexp to substitute the #include lines in the files
        map = self.generator.bld.hnodemap
        dirnodes = self.generator.bld.hnodedirs
        def repl(m):
            if m.group(1):
                s = m.group(1)

                # pokemon headers: gotta catch'em all!
                fin = s
                if s.startswith('bin/default'):
                    node = self.generator.bld.srcnode.find_resource(s.replace('bin/default/', ''))
                    if not node:
                        Logs.warn('could not find the public header for %r' % s)
                    elif node.id in map:
                        fin = map[node.id]
                    else:
                        Logs.warn('could not find the public header replacement for build header %r' % s)
                else:
                    # this part is more difficult since the path may be relative to anything
                    for dirnode in dirnodes:
                        node = dirnode.find_resource(s)
                        if node:
                             if node.id in map:
                                 fin = map[node.id]
                                 break
                             else:
                                 Logs.warn('could not find the public header replacement for source header %r %r' % (s, node))
                    else:
                        Logs.warn('-> could not find the public header for %r' % s)

                return "#include <%s>" % fin
            return ''

        txt = re_header.sub(repl, txt)

        # and write the output file
        f = None
        try:
            f = open(self.outputs[0].abspath(self.env), 'w')
            f.write(txt)
        finally:
            if f:
                f.close()

@TaskGen.feature('pubh')
def make_public_headers(self):
    """
    collect the public headers to process and to install, then
    create the substitutions (name and contents)
    """

    if not self.bld.is_install:
        # install time only (lazy)
        return

    # keep two variables
    #    hnodedirs: list of folders for searching the headers
    #    hnodemap: node ids and replacement string (node objects are unique)
    try:
        self.bld.hnodedirs.append(self.path)
    except AttributeError:
        self.bld.hnodemap = {}
        self.bld.hnodedirs = [self.bld.srcnode, self.path]

        for k in 'source4 source4/include lib/talloc lib/tevent/ source4/lib/ldb/include/'.split():
            node = self.bld.srcnode.find_dir(k)
            if node:
                self.bld.hnodedirs.append(node)

    header_path = getattr(self, 'header_path', None) or ''

    for x in self.to_list(self.headers):

        inst_path = header_install_path(x, header_path)

        dest = ''
        name = x
        if x.find(':') != -1:
            s = x.split(':')
            name = s[0]
            dest = s[1]

        inn = self.path.find_resource(name)

        if not inn:
            raise ValueError("could not find the public header %r in %r" % (name, self.path))
        out = inn.change_ext('.inst.h')
        self.create_task('header', inn, out)

        if not dest:
            dest = inn.name

        if inst_path:
            inst_path = inst_path + '/'
        inst_path = inst_path + dest

        self.bld.install_as('${INCLUDEDIR}/%s' % inst_path, out, self.env)

        self.bld.hnodemap[inn.id] = inst_path

    # create a hash (not md5) to make sure the headers are re-created if something changes
    val = 0
    lst = list(self.bld.hnodemap.keys())
    lst.sort()
    for k in lst:
        val = hash((val, k, self.bld.hnodemap[k]))
    self.bld.env.HEADER_DEPS = val



def symlink_header(task):
    '''symlink a header in the build tree'''
    src = task.inputs[0].abspath(task.env)
    tgt = task.outputs[0].bldpath(task.env)

    if os.path.lexists(tgt):
        if os.path.islink(tgt) and os.readlink(tgt) == src:
            return
        os.unlink(tgt)
    os.symlink(src, tgt)


def PUBLIC_HEADERS(bld, public_headers, header_path=None):
    '''install some headers

    header_path may either be a string that is added to the INCLUDEDIR,
    or it can be a dictionary of wildcard patterns which map to destination
    directories relative to INCLUDEDIR
    '''
    bld.SET_BUILD_GROUP('final')
    ret = bld(features=['pubh'], headers=public_headers, header_path=header_path)

    if bld.env.build_public_headers:
        # when build_public_headers is set, symlink the headers into the include/public
        # directory
        for h in TO_LIST(public_headers):
            inst_path = header_install_path(h, header_path)
            if h.find(':') != -1:
                s = h.split(":")
                h_name =  s[0]
                inst_name = s[1]
            else:
                h_name =  h
                inst_name = os.path.basename(h)
            relpath1 = os_path_relpath(bld.srcnode.abspath(), bld.curdir)
            relpath2 = os_path_relpath(bld.curdir, bld.srcnode.abspath())
            targetdir = os.path.normpath(os.path.join(relpath1, bld.env.build_public_headers, inst_path))
            if not os.path.exists(os.path.join(bld.curdir, targetdir)):
                raise Utils.WafError("missing source directory %s for public header %s" % (targetdir, inst_name))
            target = os.path.join(targetdir, inst_name)
            bld.SAMBA_GENERATOR('HEADER_%s/%s' % (relpath2, inst_name),
                                rule=symlink_header,
                                source=h_name,
                                target=target)
            if not bld.env.public_headers_list:
                bld.env.public_headers_list = []
            bld.env.public_headers_list.append(os.path.join(inst_path, inst_name))

    return ret
Build.BuildContext.PUBLIC_HEADERS = PUBLIC_HEADERS
