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

source: generate-script-source update-layout-source
build: generate-script-build update-layout-build fix-build-rights
sync: revision-bump build sync-qooxdoo-org



###################################################################################
# CLEANUP TARGETS
###################################################################################

clean:
	@echo
	@echo "  CLEANUP OF GENERATED FILES"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@rm -rf source/script

realclean: clean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (REAL)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) rm -rf build

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
	  --source-script-path ../../../$(FRAMEWORK)/source/class \
	  --generate-source-script $(SOURCELDR) \
	  --source-script-file source/script/qx.js \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:../../../$(FRAMEWORK)/source/resource \
	  --cache-directory $(CACHE)

generate-script-build:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input $(FRAMEWORK)/source/class \
	  --generate-compiled-script \
	  --compiled-script-file build/script/qx.js \
	  --optimize-strings \
	  --optimize-variables \
	  --copy-resources \
	  --resource-input $(FRAMEWORK)/source/resource \
	  --resource-output build/resource \
	  --define-runtime-setting qx.manager.object.AliasManager.resourceUri:../../resource \
	  --cache-directory $(CACHE)

generate-script-build-test:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
    --script-input $(FRAMEWORK)/source/class \
    --generate-compiled-script \
    --compiled-script-file build/script/qx.js \
    --optimize-strings \
    --optimize-variables \
    --obfuscate-identifiers --add-new-lines --add-file-ids \
    --copy-resources \
    --resource-input $(FRAMEWORK)/source/resource \
    --resource-output build/resource \
    --define-runtime-setting qx.manager.object.AliasManager.resourceUri:../../resource \
    --cache-directory $(CACHE)


###################################################################################
# FILE RELATED TARGETS
###################################################################################

update-layout-source:
	@echo
	@echo "  CREATION OF DEMO LAYOUT (SOURCE)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Generating..."
	@chmod u+x tool/layout.sh && nice -n $(NICE) tool/layout.sh source/script/layout.js source/html SOURCE

update-demo-build:
	@echo
	@echo "  CREATE COPY OF HTML FILES"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Copying files..."
	@mkdir -p build
	@cp -f source/index.html build/
	@mkdir -p build/html
	@nice -n $(NICE) rsync --recursive --links --delete --exclude=.svn source/html/* build/html
	@mkdir -p build/resource/css
	@nice -n $(NICE) rsync --recursive --links --delete --exclude=.svn source/resource/css/* build/resource/css

update-layout-build: update-demo-build
	@echo
	@echo "  CREATION OF DEMO LAYOUT (BUILD)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Generating..."
	@chmod u+x tool/layout.sh && nice -n $(NICE) tool/layout.sh build/script/layout.js build/html BUILD

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

revision-bump:
	@$(MAKE) -C ../framework revision-bump

sync-qooxdoo-org:
	@echo
	@echo "  SYNC FILES TO HOMEPAGE"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Syncing..."
	@nice -n $(NICE) rsync --checksum --recursive --archive --delete --verbose build/* root@qooxdoo.org:/var/www/qooxdoo/demo
