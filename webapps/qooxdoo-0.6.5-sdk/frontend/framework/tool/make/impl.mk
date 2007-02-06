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
# EXEC TARGETS
###################################################################################

#
# Cleanup targets
#


exec-clean:
	@echo "  * Cleaning up..."
	@$(CMD_REMOVE) $(APPLICATION_SOURCE_PATH)/$(APPLICATION_SCRIPT_FOLDERNAME)/$(APPLICATION_SCRIPT_FILENAME)
	@$(CMD_REMOVE) $(APPLICATION_BUILD_PATH)/$(APPLICATION_SCRIPT_FOLDERNAME)/$(APPLICATION_SCRIPT_FILENAME)
	@$(CMD_REMOVE) $(APPLICATION_TRANSLATION_PATH)/messages.pot
	@$(CMD_REMOVE) $(FRAMEWORK_TRANSLATION_PATH)/messages.pot

exec-distclean:
	@echo "  * Cleaning up..."
	@$(CMD_FIND) . $(FILES_TEMP) -exec $(CMD_REMOVE) {} \;
	@$(CMD_REMOVE) $(APPLICATION_SOURCE_PATH)/$(APPLICATION_SCRIPT_FOLDERNAME)
	@$(CMD_REMOVE) $(APPLICATION_BUILD_PATH)
	@$(CMD_REMOVE) $(APPLICATION_API_PATH)
	@$(CMD_REMOVE) $(APPLICATION_DEBUG_PATH)
	@$(CMD_REMOVE) $(APPLICATION_TRANSLATION_CLASS_PATH)
	@$(CMD_REMOVE) $(APPLICATION_TRANSLATION_PATH)/messages.pot
	@$(CMD_REMOVE) $(FRAMEWORK_TRANSLATION_PATH)/messages.pot
	@$(CMD_REMOVE) $(FRAMEWORK_CACHE_PATH)
	@$(CMD_REMOVE) $(FRAMEWORK_LOCALE_CLASS_PATH)
	@$(CMD_REMOVE) $(FRAMEWORK_TRANSLATION_CLASS_PATH)





#
# Generator targets
#

exec-script-source:
	@$(CMD_GENERATOR) \
	  $(COMPUTED_COMMON_INIT) \
	  $(COMPUTED_CLASS_PATH) \
	  $(COMPUTED_CLASS_URI) \
	  --generate-source-script \
	  $(COMPUTED_TEMPLATE) \
	  --source-script-file $(APPLICATION_SOURCE_PATH)/$(APPLICATION_SCRIPT_FOLDERNAME)/$(APPLICATION_SCRIPT_FILENAME) \
	  --define-runtime-setting $(FRAMEWORK_NAMESPACE).manager.object.AliasManager.resourceUri:$(FRAMEWORK_SOURCE_URI)/resource \
	  $(COMPUTED_SOURCE_INCLUDE) \
	  $(COMPUTED_SOURCE_LINEBREAKS)

exec-script-build:
	@$(CMD_GENERATOR) \
	  $(COMPUTED_COMMON_INIT) \
	  $(COMPUTED_CLASS_PATH) \
	  $(COMPUTED_RESOURCE) \
	  --generate-compiled-script \
	  --compiled-script-file $(APPLICATION_BUILD_PATH)/$(APPLICATION_SCRIPT_FOLDERNAME)/$(APPLICATION_SCRIPT_FILENAME) \
	  $(COMPUTED_BUILD_INCLUDE) \
	  $(COMPUTED_BUILD_OPTIMIZATIONS) \
	  $(COMPUTED_BUILD_LINEBREAKS)

exec-resources-build:
	@$(CMD_GENERATOR) \
	  $(COMPUTED_COMMON_INIT) \
	  $(COMPUTED_CLASS_PATH) \
	  $(COMPUTED_RESOURCE) \
	  $(COMPUTED_BUILD_INCLUDE)




#
# Utility targets
#
exec-pretty:
	@$(CMD_GENERATOR) \
	  --include-without-dependencies $(APPLICATION_NAMESPACE).* \
	  --pretty-print \
	  $(COMPUTED_CLASS_PATH)

exec-fix:
	@$(CMD_GENERATOR) \
	  --include-without-dependencies $(APPLICATION_NAMESPACE).* \
	  --fix-source \
	  $(COMPUTED_CLASS_PATH)







#
# Debug targets
#
exec-tokenizer:
	@$(CMD_GENERATOR) \
	  --include-without-dependencies $(APPLICATION_NAMESPACE).* \
	  --store-tokens \
    --token-output-directory $(APPLICATION_DEBUG_PATH)/tokens \
	  $(COMPUTED_CLASS_PATH)

exec-treegenerator:
	@$(CMD_GENERATOR) \
	  --include-without-dependencies $(APPLICATION_NAMESPACE).* \
	  --store-tree \
    --tree-output-directory $(APPLICATION_DEBUG_PATH)/tree \
	  $(COMPUTED_CLASS_PATH)







check-locales:
	@echo $(APPLICATION_LOCALES) | $(CMD_CHECKLOCALES)

ifdef APPLICATION_LOCALES

exec-localization: check-locales exec-framework-localization
exec-translation: check-locales exec-framework-translation exec-application-translation

else

exec-localization: exec-none
exec-translation: exec-none

endif





exec-framework-localization:
	@echo
	@echo "  PREPARING LOCALIZATION"
	@$(CMD_LINE)
	@mkdir -p $(FRAMEWORK_CACHE_PATH)
	@mkdir -p $(FRAMEWORK_LOCALE_CLASS_PATH)
	@echo "  * Processing locales..."
	@for LOC in $(APPLICATION_LOCALES); do \
	  echo "    - Locale: $$LOC"; \
	  mod=0; \
	  if [ ! -r $(FRAMEWORK_CACHE_PATH)/$$LOC.xml -a -r $(FRAMEWORK_LOCALE_PATH)/$$LOC.xml ]; then \
	    echo "      - Copying $$LOC.xml..."; \
	    cp -f $(FRAMEWORK_LOCALE_PATH)/$$LOC.xml $(FRAMEWORK_CACHE_PATH)/$$LOC.xml; \
	    mod=1; \
	  fi; \
	  if [ ! -r $(FRAMEWORK_CACHE_PATH)/$$LOC.xml ]; then \
	    echo "      - Downloading $$LOC.xml..."; \
	    (which wget > /dev/null 2>&1 && wget $(FRAMEWORK_CLDR_DOWNLOAD_URI)/$$LOC.xml -q -P $(FRAMEWORK_CACHE_PATH)) || \
        (which curl > /dev/null 2>&1 && curl $(FRAMEWORK_CLDR_DOWNLOAD_URI)/$$LOC.xml -s -o $(FRAMEWORK_CACHE_PATH)/$$LOC.xml); \
	    mod=1; \
		  if [ ! -r $(FRAMEWORK_CACHE_PATH)/$$LOC.xml ]; then \
		    echo "        - Download failed! Please install wget (preferred) or curl."; \
		    exit 1; \
		  fi; \
	  fi; \
	  if [ ! -r $(FRAMEWORK_LOCALE_CLASS_PATH)/$$LOC.js -o $$mod -eq 1 ]; then \
	    echo "      - Generating $$LOC.js..."; \
	    $(CMD_CLDR) -o $(FRAMEWORK_LOCALE_CLASS_PATH) $(FRAMEWORK_CACHE_PATH)/$$LOC.xml; \
	  fi; \
	done

exec-framework-translation:
	@echo
	@echo "  PREPARING FRAMEWORK TRANSLATION"
	@$(CMD_LINE)
	@echo "  * Processing source code..."
	@which xgettext > /dev/null 2>&1 || (echo "    - Please install gettext tools (xgettext)" && exit 1)
	@which msginit > /dev/null 2>&1 || (echo "    - Please install gettext tools (msginit)" && exit 1)
	@which msgmerge > /dev/null 2>&1 || (echo "    - Please install gettext tools (msgmerge)" && exit 1)

	@mkdir -p $(FRAMEWORK_TRANSLATION_PATH)
	@mkdir -p $(FRAMEWORK_TRANSLATION_CLASS_PATH)

	@rm -f $(FRAMEWORK_TRANSLATION_PATH)/messages.pot
	@touch $(FRAMEWORK_TRANSLATION_PATH)/messages.pot
	@for file in `find $(FRAMEWORK_SOURCE_PATH)/$(FRAMEWORK_CLASS_FOLDERNAME) -name "*.js"`; do \
	  LC_ALL=C xgettext --language=Java --from-code=UTF-8 \
	  -kthis.trc -kthis.tr -kthis.marktr -kthis.trn:1,2 \
	  -kManager.trc -kManager.tr -kManager.marktr -kManager.trn:1,2 \
	  --sort-by-file --add-comments=TRANSLATION \
	  -o $(FRAMEWORK_TRANSLATION_PATH)/messages.pot \
	  `find $(FRAMEWORK_SOURCE_PATH)/$(FRAMEWORK_CLASS_FOLDERNAME) -name "*.js"` 2>&1 | grep -v warning; \
	  break; done

	@echo "  * Processing translations..."
	@for LOC in $(APPLICATION_LOCALES); do \
	  echo "    - Translation: $$LOC"; \
	  if [ ! -r $(FRAMEWORK_TRANSLATION_PATH)/$$LOC.po ]; then \
  	    echo "      - Generating initial translation file..."; \
	    msginit --locale $$LOC --no-translator -i $(FRAMEWORK_TRANSLATION_PATH)/messages.pot -o $(FRAMEWORK_TRANSLATION_PATH)/$$LOC.po > /dev/null 2>&1; \
	  else \
	    echo "      - Merging translation file..."; \
	    msgmerge --update -q $(FRAMEWORK_TRANSLATION_PATH)/$$LOC.po $(FRAMEWORK_TRANSLATION_PATH)/messages.pot; \
	  fi; \
	  echo "      - Generating catalog..."; \
	  mkdir -p $(FRAMEWORK_TRANSLATION_PATH); \
	  $(CMD_MSGFMT) \
	    -n $(FRAMEWORK_TRANSLATION_CLASS_NAMESPACE) \
	    -d $(FRAMEWORK_TRANSLATION_CLASS_PATH) \
	    $(FRAMEWORK_TRANSLATION_PATH)/$$LOC.po; \
	done
	@rm -rf $(FRAMEWORK_TRANSLATION_PATH)/*~

exec-application-translation:
	@echo
	@echo "  PREPARING APPLICATION TRANSLATION"
	@$(CMD_LINE)
	@echo "  * Processing source code..."

	@which xgettext > /dev/null 2>&1 || (echo "    - Please install gettext tools (xgettext)" && exit 1)
	@which msginit > /dev/null 2>&1 || (echo "    - Please install gettext tools (msginit)" && exit 1)
	@which msgmerge > /dev/null 2>&1 || (echo "    - Please install gettext tools (msgmerge)" && exit 1)

	@mkdir -p $(APPLICATION_TRANSLATION_PATH)
	@mkdir -p $(APPLICATION_TRANSLATION_CLASS_PATH)

	@rm -f $(APPLICATION_TRANSLATION_PATH)/messages.pot
	@touch $(APPLICATION_TRANSLATION_PATH)/messages.pot
	@for file in `find $(APPLICATION_SOURCE_PATH)/$(APPLICATION_CLASS_FOLDERNAME) -name "*.js"`; do \
	  LC_ALL=C xgettext --language=Java --from-code=UTF-8 \
	  -kthis.trc -kthis.tr -kthis.marktr -kthis.trn:1,2 \
	  -kManager.trc -kManager.tr -kManager.marktr -kManager.trn:1,2 \
	  --sort-by-file --add-comments=TRANSLATION \
	  -o $(APPLICATION_TRANSLATION_PATH)/messages.pot \
	  `find $(APPLICATION_SOURCE_PATH)/$(APPLICATION_CLASS_FOLDERNAME) -name "*.js"` 2>&1 | grep -v warning; \
	  break; done

	@echo "  * Processing translations..."
	@for LOC in $(APPLICATION_LOCALES); do \
	  echo "    - Translation: $$LOC"; \
	  if [ ! -r $(APPLICATION_TRANSLATION_PATH)/$$LOC.po ]; then \
  	    echo "      - Generating initial translation file..."; \
	    msginit --locale $$LOC --no-translator -i $(APPLICATION_TRANSLATION_PATH)/messages.pot -o $(APPLICATION_TRANSLATION_PATH)/$$LOC.po > /dev/null 2>&1; \
	  else \
	    echo "      - Merging translation file..."; \
	    msgmerge --update -q $(APPLICATION_TRANSLATION_PATH)/$$LOC.po $(APPLICATION_TRANSLATION_PATH)/messages.pot; \
	  fi; \
	  echo "      - Generating catalog..."; \
	  mkdir -p $(APPLICATION_TRANSLATION_PATH); \
	  $(CMD_MSGFMT) \
	    -n $(APPLICATION_TRANSLATION_CLASS_NAMESPACE) \
	    -d $(APPLICATION_TRANSLATION_CLASS_PATH) \
	    $(APPLICATION_TRANSLATION_PATH)/$$LOC.po; \
	done
	@rm -rf $(APPLICATION_TRANSLATION_PATH)/*~







#
# File copy targets
#

exec-files-build:
	@echo
	@echo "  COPYING OF FILES"
	@$(CMD_LINE)
	@echo "  * Copying files..."
	@mkdir -p $(APPLICATION_BUILD_PATH)
	@for file in $(APPLICATION_FILES); do \
		echo "    - Processing $$file"; \
		cp -Rf $(APPLICATION_SOURCE_PATH)/$$file $(APPLICATION_BUILD_PATH)/$$file; \
	done

exec-files-api:
	@echo
	@echo "  COPYING OF FILES"
	@$(CMD_LINE)
	@echo "  * Copying files..."
	@mkdir -p $(APPLICATION_API_PATH)
	@for file in $(APIVIEWER_FILES); do \
		echo "    - Processing $$file"; \
		cp -Rf $(APIVIEWER_SOURCE_PATH)/$$file $(APPLICATION_API_PATH)/$$file; \
  done







#
# API targets
#

exec-api-data:
	@$(CMD_GENERATOR) \
	  --generate-api-documentation \
	  --api-documentation-json-file $(APPLICATION_API_PATH)/script/apidata.js \
	  $(COMPUTED_CLASS_PATH) \
	  $(COMPUTED_API_INCLUDE)

exec-api-build:
	@$(CMD_GENERATOR) \
	  --class-path $(FRAMEWORK_SOURCE_PATH)/class \
	  --class-path $(APIVIEWER_SOURCE_PATH)/class \
	  --include apiviewer \
	  --generate-compiled-script \
	  --compiled-script-file $(APPLICATION_API_PATH)/script/$(APIVIEWER_NAMESPACE).js \
	  --optimize-strings --optimize-variables \
	  --copy-resources \
	  --resource-input $(FRAMEWORK_SOURCE_PATH)/resource \
	  --resource-output $(APPLICATION_API_PATH)/resource/$(FRAMEWORK_NAMESPACE) \
	  --resource-input $(APIVIEWER_SOURCE_PATH)/resource \
	  --resource-output $(APPLICATION_API_PATH)/resource/$(APIVIEWER_NAMESPACE) \
	  --enable-resource-filter \
	  --define-runtime-setting $(FRAMEWORK_NAMESPACE).manager.object.AliasManager.resourceUri:resource/$(FRAMEWORK_NAMESPACE) \
	  --define-runtime-setting $(APIVIEWER_NAMESPACE).Application.resourceUri:resource/$(APIVIEWER_NAMESPACE) \
	  --define-runtime-setting $(APIVIEWER_NAMESPACE).Viewer.title:$(APPLICATION_API_TITLE)







#
# Publish targets
#
exec-publish:
	@echo "  * Syncing files..."
	@$(CMD_SYNC_ONLINE) $(APPLICATION_BUILD_PATH)/* $(APPLICATION_PUBLISH_PATH)







#
# None helper target
#
exec-none:
	@true






###################################################################################
# INFO TARGETS
###################################################################################

info-build:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING BUILD VERSION OF $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"

info-source:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING SOURCE VERSION OF $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"

info-api:
	@echo
	@echo "****************************************************************************"
	@echo "  GENERATING API VIEWER FOR $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"

info-pretty:
	@echo
	@echo "****************************************************************************"
	@echo "  PRETTIFYING $(APPLICATION_MAKE_TITLE) CLASSES"
	@echo "****************************************************************************"

info-fix:
	@echo
	@echo "****************************************************************************"
	@echo "  FIXING $(APPLICATION_MAKE_TITLE) CLASSES"
	@echo "****************************************************************************"

info-help:
	@echo
	@echo "****************************************************************************"
	@echo "  HELP FOR $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"

info-clean:
	@echo
	@echo "****************************************************************************"
	@echo "  CLEANING UP $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"

info-distclean:
	@echo
	@echo "****************************************************************************"
	@echo "  CLEANING UP $(APPLICATION_MAKE_TITLE)" COMPLETELY
	@echo "****************************************************************************"

info-publish:
	@echo
	@echo "****************************************************************************"
	@echo "  PUBLISHING $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"

info-debug:
	@echo
	@echo "****************************************************************************"
	@echo "  CREATING DEBUG DATA FOR $(APPLICATION_MAKE_TITLE)"
	@echo "****************************************************************************"
