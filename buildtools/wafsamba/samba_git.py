import os

def find_git(env=None):
    """Find the git binary."""
    if env is not None and 'GIT' in env:
        return env['GIT']

    # Get version from GIT
    if os.path.exists("/usr/bin/git"):
        # this is useful when doing make dist without configuring
        return "/usr/bin/git"

    return None

