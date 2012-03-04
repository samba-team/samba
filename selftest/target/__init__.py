# target.py -- Targets
# Copyright (C) 2012 Jelmer Vernooij <jelmer@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License or (at your option) any later version of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

"""Selftest target management."""

__all__ = ['Target', 'Environment', 'EnvironmentManager']


class EnvironmentDown(Exception):
    """Indicates an environment has gone down."""

    def __init__(self, msg):
        super(EnvironmentDown, self).__init__("environment went down: %s" % msg)


class UnsupportedEnvironment(Exception):
    """Indicates a particular environment is not supported."""

    def __init__(self, target, envname):
        super(UnsupportedEnvironment, self).__init__(
            "Target %s does not support environment %s" % (target, envname))


class Target(object):
    """A target for Samba tests."""

    def setup_env(self, name, prefix):
        """Setup an environment.

        :param name: name of the environment
        :param prefix: directory to create it in
        """
        raise NotImplementedError(self.setup_env)


class Environment(object):
    """An environment for Samba tests.

    Tests often need to run against a server with particular things set up,
    a "environment". This environment is provided by the test target.
    """

    def check(self):
        """Check if this environment is still up and running.

        :return: Boolean indicating whether environment is still running
        """
        raise NotImplementedError(self.check)

    def get_log(self):
        """Retrieve the last log for this environment.

        :return: String with log
        """
        raise NotImplementedError(self.get_log)

    def teardown(self):
        """Tear down an environment.

        """
        raise NotImplementedError(self.teardown)

    def get_vars(self):
        """Retrieve the environment variables for this environment.

        :return: Dictionary with string -> string values
        """
        raise NotImplementedError(self.get_vars)


class NoneEnvironment(Environment):
    """Empty environment.
    """

    def check(self):
        return True

    def get_log(self):
        return ""

    def teardown(self):
        return

    def get_vars(self):
        return {}


class NoneTarget(Target):
    """Target that can only provide the 'none' environment."""

    name = "none"

    def setup_env(self, envname, prefix):
        raise UnsupportedEnvironment(self.name, envname)


class EnvironmentManager(object):
    """Manager of environments."""

    def __init__(self, target):
        self.target = target
        self.running_envs = {}

    def get_running_env(self, name):
        envname = name.split(":")[0]
        if envname == "none":
            return NoneEnvironment()
        return self.running_envs.get(envname)

    def getlog_env(self, envname):
        env = self.get_running_env(envname)
        return env.get_log()

    def check_env(self, envname):
        """Check if an environment is still up.

        :param envname: Environment to check
        """
        env = self.get_running_env(envname)
        return env.check()

    def teardown_env(self, envname):
        """Tear down an environment.

        :param envname: Name of the environment
        """
        env = self.get_running_env(envname)
        env.teardown()
        del self.running_envs[envname]

    def teardown_all(self):
        """Teardown all environments."""
        for env in self.running_envs.iterkeys():
            self.teardown_env(env)

    def setup_env(self, envname, prefix):
        running_env = self.get_running_env(envname)
        if running_env is not None:
            if not running_env.check():
                raise EnvironmentDown(running_env.get_log())
            return running_env

        env = self.target.setup_env(envname, prefix)
        if env is None:
            return None

        self.running_envs[envname] = env

        return env
