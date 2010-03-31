# See README for copyright and licensing details.

PYTHON=python
SOURCES=$(shell find testtools -name "*.py")

check:
	PYTHONPATH=$(PWD) $(PYTHON) -m testtools.run testtools.tests.test_suite

TAGS: ${SOURCES}
	ctags -e -R testtools/

tags: ${SOURCES}
	ctags -R testtools/

clean:
	rm -f TAGS tags
	find testtools -name "*.pyc" -exec rm '{}' \;

release:
	./setup.py sdist upload --sign

apidocs:
	pydoctor --make-html --add-package testtools \
		--docformat=restructuredtext --project-name=testtools \
		--project-url=https://launchpad.net/testtools


.PHONY: check clean release apidocs
