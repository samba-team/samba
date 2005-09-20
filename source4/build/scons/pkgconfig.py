# Based on the examples from the scons wiki

def CheckPKGConfig(context, version):
	context.Message('Checking for pkg-config... ')
	ret = context.TryAction('pkg-config --atleast-pkgconfig-version=%s' % version)[0]
	context.Result(ret)
	return ret

def CheckPackage(context, name):
	context.Message('Checking for %s... ' % name)
	ret = context.TryAction('pkg-config --exists \'%s\'' % name)[0]
	context.Result(ret)
	return ret
