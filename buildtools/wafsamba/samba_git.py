import os
import subprocess

def find_git(env=None):
    """Find the git binary."""
    if env is not None and 'GIT' in env:
        return env.get_flat('GIT')

    # Get version from GIT
    if os.path.exists("/usr/bin/git"):
        # this is useful when doing make dist without configuring
        return "/usr/bin/git"

    return None


def has_submodules(path):
    """Check whether a source directory is git-versioned and has submodules.

    :param path: Path to Samba source directory
    """
    return (os.path.isdir(os.path.join(path, ".git")) and
            os.path.isfile(os.path.join(path, ".gitmodules")))


def read_submodule_status(path, env=None):
    """Check status of submodules.

    :param path: Path to git directory
    :param env: Optional waf environment
    :return: Yields tuples with submodule relpath and status
        (one of: 'out-of-date', 'not-checked-out', 'up-to-date')
    :raise RuntimeError: raised when parsing of 'git submodule status' output
        fails.
    """
    if not has_submodules(path):
        # No point in running git.
        return
    git = find_git(env)
    if git is None:
        return
    p = subprocess.Popen([git, "submodule", "status"], stdout=subprocess.PIPE,
        cwd=path)
    (stdout, stderr) = p.communicate(None)
    for l in stdout.splitlines():
        l = l.rstrip()
        status = l[0]
        l = l[1:]
        parts = l.split(" ")
        if len(parts) > 2 and status in ("-", "+"):
            yield (parts[1], "out-of-date")
        elif len(parts) == 2 and status == "-":
            yield (parts[1], "not-checked-out")
        elif len(parts) > 2 and status == " ":
            yield (parts[1], "up-to-date")
        else:
            raise RuntimeError("Unable to parse submodule status: %r, %r" % (status, parts))
