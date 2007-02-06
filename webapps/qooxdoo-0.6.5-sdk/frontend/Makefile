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

################################################################################
# PUBLIC VARIABLES
################################################################################

QOOXDOO_PATH = ..




################################################################################
# INCLUDE CORE
################################################################################

include $(QOOXDOO_PATH)/frontend/framework/tool/make/framework.mk





################################################################################
# PRIVATE VARIABLES
################################################################################

RELEASE_BUILD_UNIX = release/temp/build/unix/qooxdoo-$(FRAMEWORK_VERSION)-build
RELEASE_BUILD_DOS = release/temp/build/dos/qooxdoo-$(FRAMEWORK_VERSION)-build

RELEASE_SDK_UNIX = release/temp/sdk/unix/qooxdoo-$(FRAMEWORK_VERSION)-sdk
RELEASE_SDK_DOS = release/temp/sdk/dos/qooxdoo-$(FRAMEWORK_VERSION)-sdk

APPLICATIONS = apiviewer feedreader sample showcase webmail
SDK_COPY = Makefile application/Makefile application/index.html







################################################################################
# COMMON TARGETS
################################################################################

source:
	@$(MAKE) -s -C application source

build:
	@$(MAKE) -s -C application build

api:
	@$(MAKE) -s -C application api

all:
	@$(MAKE) -s -C application all

locales:
	@$(MAKE) -s -C application locales

pretty: framework-pretty
	@$(MAKE) -s -C application pretty

fix: framework-fix
	@$(MAKE) -s -C application fix

publish:
	@$(MAKE) -s -C application publish

clean:
	@$(MAKE) -s -C application clean

distclean:
	@$(MAKE) -s -C application distclean
	@$(MAKE) -s release-distclean
	@$(MAKE) -s framework-distclean






################################################################################
# FRAMEWORK TARGETS
################################################################################

framework-distclean:
	@echo
	@echo "****************************************************************************"
	@echo "  CLEANING UP FRAMEWORK COMPLETELY"
	@echo "****************************************************************************"
	@echo "  * Cleaning up..."
	@$(CMD_REMOVE) $(FRAMEWORK_CACHE_PATH)
	@$(CMD_REMOVE) $(FRAMEWORK_LOCALE_CLASS_PATH)
	@$(CMD_REMOVE) $(FRAMEWORK_TRANSLATION_CLASS_PATH)
	@$(CMD_REMOVE) application/skeleton.tar.gz
	@$(CMD_REMOVE) application/skeleton.zip
	@$(CMD_FIND) $(FRAMEWORK_PATH) $(FILES_TEMP) -exec $(CMD_REMOVE) {} \;
	@$(CMD_REMOVE) $(FRAMEWORK_TOOL_PATH)/icon/temp


framework-pretty:
	@echo
	@echo "****************************************************************************"
	@echo "  PRETTIFYING FRAMEWORK CLASSES"
	@echo "****************************************************************************"
	@$(CMD_GENERATOR) \
	  --pretty-print \
	  --class-path $(FRAMEWORK_SOURCE_PATH)/$(FRAMEWORK_CLASS_FOLDERNAME)

framework-fix:
	@echo
	@echo "****************************************************************************"
	@echo "  FIXING FRAMEWORK CLASSES"
	@echo "****************************************************************************"
	@$(CMD_GENERATOR) \
	  --fix-source \
	  --class-path $(FRAMEWORK_SOURCE_PATH)/$(FRAMEWORK_CLASS_FOLDERNAME)




################################################################################
# MIGRATION TARGETS
################################################################################


checkout-migration:
	@echo
	@echo "****************************************************************************"
	@echo "  MIGRATE CHECKOUT"
	@echo "****************************************************************************"
	@if [ 1 ]; then \
	  migrate_options="--class-path framework/source/class --migration-input application/sample/source/html/"; \
	  for APPLICATION in $(APPLICATIONS); do \
	    if [ -d application/$$APPLICATION/source/class ]; then \
	      migrate_options="$${migrate_options} --class-path application/$$APPLICATION/source/class"; \
	    fi; \
	  done; \
	  $(CMD_GENERATOR) \
	    --migrate-source --migration-target `echo $(FRAMEWORK_VERSION) | cut -d'-' -f1` \
	    $${migrate_options}; \
	 fi;







################################################################################
# SKELETON TARGETS
################################################################################

SKELETON_TEMP_UNIX = temp-skeleton-unix
SKELETON_TEMP_DOS = temp-skeleton-dos

SKELETON_FILES = Makefile source/class source/resource source/index.html


info-skeleton-unix:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING UNIX VERSION OF SKELETON"
	@echo "****************************************************************************"

info-skeleton-dos:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING DOS VERSION OF SKELETON"
	@echo "****************************************************************************"

skeleton-unix: info-skeleton-unix exec-skeleton-unix exec-skeleton-unix-post exec-skeleton-unix-clean
skeleton-dos: info-skeleton-dos exec-skeleton-dos exec-skeleton-dos-post exec-skeleton-dos-clean

exec-skeleton-unix: exec-skeleton-unix-collect exec-skeleton-unix-archive
exec-skeleton-dos: exec-skeleton-dos-collect exec-skeleton-dos-archive

exec-skeleton-unix-collect:
	@echo "  * Collecting skeleton files..."
	@for FILE in $(SKELETON_FILES); do \
    	echo "    - $$FILE"; \
    	$(CMD_DIR) `dirname $(SKELETON_TEMP_UNIX)/skeleton/$$FILE`; \
	  	$(CMD_SYNC_OFFLINE) application/skeleton/$$FILE `dirname $(SKELETON_TEMP_UNIX)/skeleton/$$FILE`; \
  	done

exec-skeleton-unix-archive:
	@echo "  * Cleaning up target folders..."
	@$(CMD_FIND) $(SKELETON_TEMP_UNIX) $(FILES_TEMP) -exec $(CMD_REMOVE) {} \;

	@echo "  * Switching to Unix line endings..."
	@$(CMD_FIND) $(SKELETON_TEMP_UNIX) $(FILES_TEXT) $(CMD_ANY2UNIX)

	@echo "  * Fixing executables..."
	@$(CMD_FIND) $(SKELETON_TEMP_UNIX) $(FILES_EXEC) -exec $(CMD_MKEXEC) {} \;

	@echo "  * Building skeleton archive..."
	@$(CMD_REMOVE) $(SKELETON_TEMP_UNIX)/skeleton.tar.gz
	@cd $(SKELETON_TEMP_UNIX); $(CMD_TAR_CREATE) skeleton.tar.gz skeleton
	@$(CMD_REMOVE) $(SKELETON_TEMP_UNIX)/skeleton

exec-skeleton-dos-collect:
	@echo "  * Collecting skeleton files..."
	@for FILE in $(SKELETON_FILES); do \
    	echo "    - $$FILE"; \
    	$(CMD_DIR) `dirname $(SKELETON_TEMP_DOS)/skeleton/$$FILE`; \
	  	$(CMD_SYNC_OFFLINE) application/skeleton/$$FILE `dirname $(SKELETON_TEMP_DOS)/skeleton/$$FILE`; \
  	done

exec-skeleton-dos-archive:
	@echo "  * Cleaning up target folders..."
	@$(CMD_FIND) $(SKELETON_TEMP_DOS) $(FILES_TEMP) -exec $(CMD_REMOVE) {} \;

	@echo "  * Switching to DOS line endings..."
	@$(CMD_FIND) $(SKELETON_TEMP_DOS) $(FILES_TEXT) $(CMD_ANY2DOS)

	@echo "  * Fixing executables..."
	@$(CMD_FIND) $(SKELETON_TEMP_DOS) $(FILES_EXEC) -exec $(CMD_MKEXEC) {} \;

	@echo "  * Building skeleton archive..."
	@$(CMD_REMOVE) $(SKELETON_TEMP_DOS)/skeleton.zip
	@cd $(SKELETON_TEMP_DOS); $(CMD_ZIP_CREATE) skeleton.zip skeleton
	@$(CMD_REMOVE) $(SKELETON_TEMP_DOS)/skeleton

exec-skeleton-unix-post:
	@$(CMD_SYNC_OFFLINE) $(SKELETON_TEMP_UNIX)/skeleton.tar.gz application/
	@echo
	@echo "  * Created application/skeleton.tar.gz"
	@echo "    Please extract to a location outside this qooxdoo folder."

exec-skeleton-dos-post:
	@$(CMD_SYNC_OFFLINE) $(SKELETON_TEMP_DOS)/skeleton.zip application/
	@echo
	@echo "  * Created application/skeleton.zip"
	@echo "    Please extract to a location outside this qooxdoo folder."

exec-skeleton-unix-clean:
	@$(CMD_REMOVE) $(SKELETON_TEMP_UNIX)

exec-skeleton-dos-clean:
	@$(CMD_REMOVE) $(SKELETON_TEMP_DOS)








################################################################################
# RELEASE TARGETS
################################################################################

release-distclean:
	@echo
	@echo "****************************************************************************"
	@echo "  CLEANING UP RELEASE COMPLETELY"
	@echo "****************************************************************************"
	@echo "  * Cleaning up..."
	@$(CMD_REMOVE) release




release: release-sdk release-build
release-fast: release-build-fast release-sdk-fast




release-build: build release-build-fast
release-build-fast: release-build-info release-build-unix release-build-dos

release-build-info:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING BUILD VERSION OF RELEASE $(FRAMEWORK_VERSION)"
	@echo "****************************************************************************"

release-build-unix:
	@echo
	@echo "  SYNCHRONISATION OF BUILD RELEASE (UNIX VERSION)"
	@echo "----------------------------------------------------------------------------"

	@echo "  * Copying info files..."
	@$(CMD_DIR) $(RELEASE_BUILD_UNIX)
	@for FILE in `find ../ -maxdepth 1 -type f -name "[A-Z]*"`; do \
	  echo "    - `basename $$FILE`"; \
	  cp -f $$FILE $(RELEASE_BUILD_UNIX); \
	done

	@echo "  * Synchronizing applications..."
	@for APPLICATION in $(APPLICATIONS); do \
		echo "    - $$APPLICATION"; \
	  $(CMD_DIR) $(RELEASE_BUILD_UNIX)/frontend/$$APPLICATION; \
		if [ ! -r application/$$APPLICATION/build ]; then \
		  echo "      - Missing build folder! Run $(MAKE) build first!"; \
		  exit 1; \
		fi; \
	  $(CMD_SYNC_OFFLINE) application/$$APPLICATION/build/* $(RELEASE_BUILD_UNIX)/frontend/$$APPLICATION; \
	done
	@echo "  * Generating index.html..."
	@cat application/index.html | \
		sed 's/class="source"/class="source hide"/g' | \
		sed 's/class="build"//g' > $(RELEASE_BUILD_UNIX)/frontend/index.html

	@echo "  * Switching to Unix line endings..."
	@$(CMD_FIND) $(RELEASE_BUILD_UNIX) $(FILES_TEXT) $(CMD_ANY2UNIX)

	@echo "  * Generating tar archive..."
	@cd release/temp/build/unix; $(CMD_REMOVE) qooxdoo-$(FRAMEWORK_VERSION)-build.tar.gz; $(CMD_NICE) tar cfzp ../../../qooxdoo-$(FRAMEWORK_VERSION)-build.tar.gz qooxdoo-$(FRAMEWORK_VERSION)-build

release-build-dos:
	@echo
	@echo "  SYNCHRONISATION OF BUILD RELEASE (DOS VERSION)"
	@echo "----------------------------------------------------------------------------"

	@echo "  * Copying info files..."
	@$(CMD_DIR) $(RELEASE_BUILD_DOS)
	@for FILE in `find ../ -maxdepth 1 -type f -name "[A-Z]*"`; do \
	  echo "    - `basename $$FILE`"; \
	  cp -f $$FILE $(RELEASE_BUILD_DOS); \
	done

	@echo "  * Synchronizing applications..."
	@for APPLICATION in $(APPLICATIONS); do \
		echo "    - $$APPLICATION"; \
	  $(CMD_DIR) $(RELEASE_BUILD_DOS)/frontend/$$APPLICATION; \
		if [ ! -r application/$$APPLICATION/build ]; then \
		  echo "      - Missing build folder! Run $(MAKE) build first!"; \
		  exit 1; \
		fi; \
	  $(CMD_SYNC_OFFLINE) application/$$APPLICATION/build/* $(RELEASE_BUILD_DOS)/frontend/$$APPLICATION; \
	done

	@echo "  * Generating index.html..."
	@cat application/index.html | \
		sed 's/class="source"/class="source hide"/g' | \
		sed 's/class="build"//g' > $(RELEASE_BUILD_DOS)/frontend/index.html

	@echo "  * Switching to DOS line endings..."
	@$(CMD_FIND) $(RELEASE_BUILD_DOS) $(FILES_TEXT) $(CMD_ANY2DOS)

	@echo "  * Generating zip archive..."
	@cd release/temp/build/dos; $(CMD_REMOVE) qooxdoo-$(FRAMEWORK_VERSION)-build.zip; $(CMD_NICE) zip -rq ../../../qooxdoo-$(FRAMEWORK_VERSION)-build.zip qooxdoo-$(FRAMEWORK_VERSION)-build









release-sdk: distclean release-sdk-fast
release-sdk-fast: release-sdk-info release-sdk-unix release-sdk-dos

release-sdk-info:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING SDK VERSION OF RELEASE $(FRAMEWORK_VERSION)"
	@echo "****************************************************************************"

release-sdk-unix:
	@echo
	@echo "  SYNCHRONISATION OF SDK RELEASE (UNIX VERSION)"
	@echo "----------------------------------------------------------------------------"

	@echo "  * Copying info files..."
	@$(CMD_DIR) $(RELEASE_SDK_UNIX)
	@for FILE in `find ../ -maxdepth 1 -type f -name "[A-Z]*"`; do \
	  echo "    - `basename $$FILE`"; \
	  cp -f $$FILE $(RELEASE_SDK_UNIX); \
	done

	@echo "  * Synchronizing applications..."
	@for APPLICATION in $(APPLICATIONS); do \
		echo "    - $$APPLICATION"; \
	  $(CMD_DIR) $(RELEASE_SDK_UNIX)/frontend/application/$$APPLICATION; \
	  $(CMD_SYNC_OFFLINE) --exclude script --exclude build --exclude publish application/$$APPLICATION/* $(RELEASE_SDK_UNIX)/frontend/application/$$APPLICATION; \
	done

	@echo "  * Synchronizing framework..."
	@$(CMD_DIR) $(RELEASE_SDK_UNIX)/frontend/framework
	@$(CMD_SYNC_OFFLINE) --exclude .cache --exclude tool/icon/themes --exclude tool/icon/temp framework/* $(RELEASE_SDK_UNIX)/frontend/framework

	@echo "  * Copying remaining SDK files..."
	@for ITEM in $(SDK_COPY); do \
	  cp -f $$ITEM $(RELEASE_SDK_UNIX)/frontend/$$ITEM; \
	done

	@$(MAKE) -s exec-skeleton-unix
	@$(CMD_SYNC_OFFLINE) $(SKELETON_TEMP_UNIX)/skeleton.tar.gz $(RELEASE_SDK_UNIX)/frontend/application/
	@$(MAKE) -s exec-skeleton-unix-clean

	@echo "  * Generating tar archive..."
	@cd release/temp/sdk/unix; $(CMD_REMOVE) qooxdoo-$(FRAMEWORK_VERSION)-sdk.tar.gz; $(CMD_TAR_CREATE) ../../../qooxdoo-$(FRAMEWORK_VERSION)-sdk.tar.gz qooxdoo-$(FRAMEWORK_VERSION)-sdk

release-sdk-dos:
	@echo
	@echo "  SYNCHRONISATION OF SDK RELEASE (DOS VERSION)"
	@echo "----------------------------------------------------------------------------"

	@echo "  * Copying info files..."
	@$(CMD_DIR) $(RELEASE_SDK_DOS)
	@for FILE in `find ../ -maxdepth 1 -type f -name "[A-Z]*"`; do \
	  echo "    - `basename $$FILE`"; \
	  cp -f $$FILE $(RELEASE_SDK_DOS); \
	done

	@echo "  * Synchronizing applications..."
	@for APPLICATION in $(APPLICATIONS); do \
		echo "    - $$APPLICATION"; \
	  $(CMD_DIR) $(RELEASE_SDK_DOS)/frontend/application/$$APPLICATION; \
	  $(CMD_SYNC_OFFLINE) --exclude script --exclude build --exclude publish application/$$APPLICATION/* $(RELEASE_SDK_DOS)/frontend/application/$$APPLICATION; \
	done

	@echo "  * Synchronizing framework..."
	@$(CMD_DIR) $(RELEASE_SDK_DOS)/frontend/framework
	@$(CMD_SYNC_OFFLINE) --exclude .cache --exclude tool/icon/themes --exclude tool/icon/temp framework/* $(RELEASE_SDK_DOS)/frontend/framework

	@echo "  * Copying remaining SDK files..."
	@for ITEM in $(SDK_COPY); do \
	  cp -f $$ITEM $(RELEASE_SDK_DOS)/frontend/$$ITEM; \
	done

	@$(MAKE) -s exec-skeleton-dos
	@$(CMD_SYNC_OFFLINE) $(SKELETON_TEMP_DOS)/skeleton.zip $(RELEASE_SDK_DOS)/frontend/application/
	@$(MAKE) -s exec-skeleton-dos-clean

	@echo "  * Generating zip archive..."
	@cd release/temp/sdk/dos; $(CMD_REMOVE) qooxdoo-$(FRAMEWORK_VERSION)-sdk.zip; $(CMD_ZIP_CREATE) ../../../qooxdoo-$(FRAMEWORK_VERSION)-sdk.zip qooxdoo-$(FRAMEWORK_VERSION)-sdk
