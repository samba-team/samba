###################################################################################
# VARIABLES
###################################################################################

FRAMEWORK=../framework
GENERATOR=$(FRAMEWORK)/tool/generator.py
CACHE=$(FRAMEWORK)/.cache
SOURCELOADER=
NICE=10

ifneq ($(SOURCELOADER),)
  SOURCELDR = --source-loader-type $(SOURCELOADER)
else
  SOURCELDR =
endif


###################################################################################
# DEFAULT TARGET
###################################################################################

all: build



###################################################################################
# COMMON TARGETS
###################################################################################

source: generate-script-source generate-data-source
build: generate-script-build generate-data-build copy-index-file fix-build-rights
sync: build sync-qooxdoo-org
pretty: generate-pretty
fix: generate-fix



###################################################################################
# CLEANUP TARGETS
###################################################################################

clean:
	@echo
	@echo "  CLEANUP OF GENERATED FILES"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@rm -f source/script/api.js source/script/data.js
	@rm -f build/script/api.js build/script/data.js
	@rm -rf build/xml source/xml

realclean: clean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (REAL)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) rm -rf build source/script

distclean: realclean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (DIST)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) find . -name "*~" -o -name "*.bak" -o -name "*.old" | xargs rm -rf
	@nice -n $(NICE) rm -rf $(CACHE)



###################################################################################
# GENERATOR TARGETS
###################################################################################

generate-script-source:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --source-script-path ../$(FRAMEWORK)/source/class \
	  --script-input source/class \
	  --source-script-path class \
	  --include api \
	  --generate-source-script $(SOURCELDR) \
	  --source-script-file source/script/api.js \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:../$(FRAMEWORK)/source/resource \
	  --cache-directory $(CACHE)

generate-script-build:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --resource-input $(FRAMEWORK)/source/resource \
	  --resource-output build/resource/qooxdoo \
	  --script-input source/class \
	  --resource-input source/resource \
	  --resource-output build/resource \
	  --include api \
	  --generate-compiled-script \
	  --compiled-script-file build/script/api.js \
	  --optimize-strings \
	  --optimize-variables \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:resource/qooxdoo \
	  --copy-resources \
	  --cache-directory $(CACHE)

generate-data-source:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --generate-api-documentation \
	  --api-documentation-json-file source/script/data.js \
	  --cache-directory $(CACHE)

generate-data-build:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --generate-api-documentation \
	  --api-documentation-json-file build/script/data.js \
	  --cache-directory $(CACHE)

generate-data-source-xml:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --generate-api-documentation \
	  --api-documentation-xml-file source/xml/data.xml \
	  --cache-directory $(CACHE)

generate-data-build-xml:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --generate-api-documentation \
	  --api-documentation-xml-file build/xml/data.xml \
	  --cache-directory $(CACHE)

generate-pretty:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --script-input $(FRAMEWORK)/source/class \
	  --include-without-dependencies api.* \
	  --pretty-print \
	  --cache-directory $(CACHE)

generate-fix:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --script-input $(FRAMEWORK)/source/class \
	  --include-without-dependencies api.* \
	  --fix-source \
	  --cache-directory $(CACHE)



###################################################################################
# FILE RELATED TARGETS
###################################################################################

copy-index-file:
	@echo
	@echo "  CREATE COPY OF HTML FILE"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Copying file..."
	@cp -f source/index.html build/index.html

fix-build-rights:
	@echo
	@echo "  FIX RIGHTS ON BUILD FILES"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Fixing file rights..."
	@nice -n $(NICE) find build -type d | xargs chmod a+rx
	@nice -n $(NICE) find build -type f | xargs chmod a+r






###################################################################################
# ONLINE TARGETS
###################################################################################

sync-qooxdoo-org:
	@echo
	@echo "  SYNC FILES TO HOMEPAGE"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Syncing..."
	@nice -n $(NICE) rsync --checksum --recursive --archive --delete --verbose build/* root@qooxdoo.org:/var/www/qooxdoo/api
