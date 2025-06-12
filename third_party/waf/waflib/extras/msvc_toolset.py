#!/usr/bin/env python3
"""Tool used to discover Visual Studio side-by-side (SxS) installations.

Implements an alternative discovery mechanism for Visual Studio 2017 and
newer to support SxS toolsets and specific Windows SDK releases. This acts
as a replacement for msvc.py to allow developers to pin to specific Visual
Studio and Windows SDK releases.

Usage::

	$ waf configure --msvc_version='msvc 17.9' --winsdk-version='8.1'

or::

	def configure(ctx):
		ctx.env.MSVC_VERSIONS = ['msvc 17.9']
		ctx.env.WINSDK_VERSION = '8.1'
		ctx.load('msvc_toolset')
"""

import contextlib
import functools
import glob
import inspect
import json
import logging
import os
import re
import subprocess
import tempfile

try:  # noqa: SIM105
	from waflib import Configure, Context, Options
except ImportError:
	pass


@functools.total_ordering
class _VisualStudioToolset(object):  # noqa: UP004
	"""Class used to represent a Visual Studio toolset installation."""

	VS_INSTALL_ROOT = '{}\\Microsoft Visual Studio'.format(
		os.environ.get('PROGRAMFILES(X86)')
		or os.environ.get('PROGRAMFILES')
		or 'C:\\Program Files (x86)',
	)

	_discovered = None

	@classmethod
	def discover(cls, log_debug, runner=None):  # noqa: ANN001, ANN206
		"""Memoize the Visual Studio toolsets installed.

		:param log_debug: Python logging.Logger.debug method
		:type log_debug: Callable[[str], None]
		:param runner: Method used to invoke a subprocess
		:type runner: Callable[[list(str)], str], optional
		:return: collection of toolsets installed
		:rtype: list[_VisualStudioToolset]
		"""
		if cls._discovered is None:
			run_process = runner or functools.partial(
				subprocess.check_output,
				universal_newlines=True,
			)
			listing = run_process(
				[
					'{}/Installer/vswhere.exe'.format(cls.VS_INSTALL_ROOT),  # noqa: UP032
					'-all',
					'-products',
					'*',
					'-format',
					'json',
					'-utf8',
					'-include',
					'packages',
				],
			)

			installations = json.loads(listing)

			vc_components = '{}(?:{})'.format(
				re.escape('Microsoft.VisualStudio.Component.VC.'),
				'|'.join(  # noqa: FLY002
					[
						r'Tools\.(?!14)',
						'140',
						'v141',
						r'(?:Tools\.)?14(?:\.\d+)+',
					],
				),
			)
			re_sxs_ids = re.compile(vc_components)

			vc_components = (
				'{}:{}'.format(install['installationVersion'], package['id'])
				for install in installations
				for package in install['packages']
				if re_sxs_ids.match(package['id'])
			)

			for component in vc_components:
				log_debug(component)

			sxs_minimum_version = 15
			installs = (
				(install['installationVersion'], install['installationPath'])
				for install in installations
				if next(int(i) for i in install['installationVersion'].split('.'))
				>= sxs_minimum_version
			)

			toolset_dirs = {
				cls(install_version, toolset_dir)
				for install_version, install_path in installs
				for toolset_dir in glob.iglob('{}/VC/Tools/MSVC/*'.format(install_path))  # noqa: PTH207, UP032
				if os.path.isdir('{}/bin'.format(toolset_dir))  # noqa: PTH112, UP032
			}

			cls._discovered = sorted(toolset_dirs)

		return cls._discovered

	def __init__(self, install_version, directory):  # noqa: ANN001, ANN204
		"""Construct an instance of the class.

		:param install_version: Visual Studio version containing the toolset
		:type install_version: str
		:param directory: Fully qualified path to the toolset directory
		:type directory: os.pathLike
		"""
		self.install_version = install_version
		self._path = directory
		self._vcvars_ver = os.path.basename(directory)  # noqa: PTH119
		self._vcvarsall = os.path.normpath(
			'{}/../../../Auxiliary/Build/vcvarsall.bat'.format(directory),  # noqa: UP032
		)

		version = tuple(int(i) for i in self._vcvars_ver.split('.'))
		# https://learn.microsoft.com/en-us/cpp/overview/compiler-versions?view=msvc-170
		if version < (14, 20):
			self._visual_studio_version = (15, version[1] - 7)
		elif version < (14, 30):
			self._visual_studio_version = (
				16,
				version[1]
				- 20
				# 16.9 distinguished from 16.8 by build number
				# this also accounts for the minor version not
				# being updated for 16.10
				+ bool(version >= (14, 28, 29910))
				# 16.11 distinguished from 16.10 by build number
				+ bool(version >= (14, 29, 30129)),
			)
		else:
			self._visual_studio_version = (17, version[1] - 30)

	def __eq__(self, other):  # noqa: ANN001, ANN204
		"""Return if the instance is equal to another instance of this class.

		:param other: Another toolset to compare against
		:type other: _VisualStudioToolset
		:return: True if the toolsets represent the same Visual Studio version, False otherwise
		:rtype: bool
		"""
		return self._visual_studio_version == other._visual_studio_version

	def __lt__(self, other):  # noqa: ANN001, ANN204
		"""Return if the instance is less than another instance of this class.

		:param other: Another toolset to compare against
		:type other: _VisualStudioToolset
		:return: True if the toolsets represent an older Visual Studio version, False otherwise
		:rtype: bool
		"""
		return self._visual_studio_version < other._visual_studio_version

	def __hash__(self):  # noqa: ANN204
		"""Utilize _path member as class hash.

		:return: Python hash of the toolset directory
		:rtype: int
		"""
		return hash(self._path)

	def __str__(self):  # noqa: ANN204
		"""Obtain the string representation of the class.

		:return: A uniquely identified string representation for the toolset
		:rtype: str
		"""
		return '{:<16s} {:<6s} {}'.format(
			'{}:'.format(self.install_version),  # noqa: UP032
			'{}:'.format(self.visual_studio_version),  # noqa: UP032
			self.vc_version,
		)

	@property
	def visual_studio_version(self):  # noqa: ANN202
		"""Obtain the Visual Studio version associated with this toolset.

		:return: Visual Studio major and minor version.
		:rtype: str
		"""
		return '{}.{}'.format(*self._visual_studio_version)

	@property
	def vcvarsall(self):  # noqa: ANN202
		"""Obtain the configuration script.

		:return: Fully qualified path to vcvarsall.bat
		:rtype: str
		"""
		return self._vcvarsall

	@property
	def vc_version(self):  # noqa: ANN202
		"""Obtain the vc_version option.

		:return: vc_version used to configure toolset in vcvarsall.bat
		:rtype: str
		"""
		return self._vcvars_ver

	def cl(self):  # noqa: ANN202
		"""Run and return the compiler output.

		:return: CL output on success, or vcvarsall output on error
		:rtype: list(str)
		"""
		contents = inspect.cleandoc(
			"""
			@echo off
			call "{}" amd64 -vcvars_ver={}
			if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL%
			cl
			""",
		).format(self.vcvarsall, self._vcvars_ver)

		with tempfile.NamedTemporaryFile('w', suffix='.cmd', delete=False) as tmp:
			try:
				tmp.write(contents)
				tmp.close()
				process = subprocess.Popen(  # noqa: S603
					[tmp.name],
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE,
					universal_newlines=True,
					shell=False,
				)
				stdout, stderr = process.communicate()
				if process.returncode:
					return stdout.splitlines() + stderr.splitlines()
				return stderr.splitlines()
			finally:
				os.unlink(tmp.name)  # noqa: PTH108


def options(ctx):  # noqa: ANN001, ANN201
	"""Configure the Microsoft compiler(s) Waf options.

	:param ctx: Waf context associated with option handling
	:type ctx: waflib.Options.OptionContext
	"""
	ctx.load('msvc')

	winsdk_default = re.findall(
		r'(8\.1|10(?:\.\d+)+)',
		os.environ.get('WINDOWSSDKVERSION', ''),
	) or ['']

	ctx.add_option(
		'--winsdk-version',
		type=str,
		help='Windows SDK Versions, eg: 10.0.19041.0',
		default=winsdk_default[0],
	)


@contextlib.contextmanager
def _use_vs_toolsets_discovery():  # noqa: ANN202
	"""Patch the Waf msvc tools VS2017+ discovery."""
	msvc = Context.load_tool('msvc')

	def gather_vswhere_versions(ctx, versions):  # noqa: ANN001, ANN202
		"""Detect the Microsoft SxS compiler(s) for Waf.

		:param ctx: Waf context associated with tool configuration
		:type ctx: waflib.Configure.ConfigurationContext
		:param versions: The upstream msvc versions dictionary
		:type versions: dict
		"""
		msvc.gather_vswhere_versions(ctx, versions)
		log_debug = functools.partial(
			logging.getLogger('waflib').debug,
			extra={'zone': 'msvc_toolset'},
		)

		for toolset in _VisualStudioToolset.discover(log_debug, ctx.cmd_and_log):
			waf_version = 'msvc {}'.format(toolset.visual_studio_version)  # noqa: UP032
			if waf_version in versions:
				log_debug("Replacing msvc's '%s' with msvc_toolset's '%s'", waf_version, toolset)
			versions[waf_version] = {
				target: msvc.target_compiler(
					ctx,
					'msvc',
					realtarget,
					toolset.visual_studio_version,
					'{} {} -vcvars_ver={}'.format(
						target,
						getattr(Options.options, 'winsdk_version', '')
						or ctx.env.WINSDK_VERSION
						or '',
						toolset.vc_version,
					),
					toolset.vcvarsall,
				)
				for target, realtarget in msvc.all_msvc_platforms[::-1]
			}

	try:
		Configure.conf(gather_vswhere_versions)
		yield
	finally:
		Configure.conf(msvc.gather_vswhere_versions)


def configure(ctx):  # noqa: ANN001, ANN201
	"""Configure the Microsoft compiler(s) in Waf.

	:param ctx: Waf context associated with tool configuration
	:type ctx: waflib.Configure.ConfigurationContext
	"""
	with _use_vs_toolsets_discovery():
		ctx.load('msvc')


if __name__ == '__main__':
	logger = logging.getLogger('msvc_toolset')
	logging.basicConfig(
		format='%(message)s',
		level=getattr(logging, os.environ.get('LOG_LEVEL', 'info').upper()),
	)

	for toolset in _VisualStudioToolset.discover(logger.debug):
		logger.info(toolset)
		cl_info = '\n    '.join(line for line in toolset.cl() if line)
		logger.info('    %s', cl_info)
