################################################################################
#
#  qooxdoo - the new era of web development
#
#  http://qooxdoo.org
#
#  Copyright:
#    2006-2007 1&1 Internet AG, Germany, http://www.1and1.org
#
#  License:
#    LGPL: http://www.gnu.org/licenses/lgpl.html
#    EPL: http://www.eclipse.org/org/documents/epl-v10.php
#    See the LICENSE file in the project's top-level directory for details.
#
#  Authors:
#    * Sebastian Werner (wpbasti)
#    * Andreas Ecker (ecker)
#    * Fabian Jakobs (fjakobs)
#
################################################################################

###################################################################################
# TARGETS
###################################################################################

#
# Target definitions
#

.PHONY: source build api all locales pretty fix help clean distclean publish debug

source: info-source exec-localization exec-translation exec-script-source
build: info-build exec-localization exec-translation exec-script-build exec-files-build
api: info-api exec-localization exec-translation exec-api-build exec-api-data exec-files-api
all: source build api

locales: exec-localization exec-translation

pretty: info-pretty exec-pretty
fix: info-fix exec-fix

help: info-help

clean: info-clean exec-clean
distclean: info-distclean exec-distclean

publish: build info-publish exec-publish

debug: info-debug exec-tokenizer exec-treegenerator
