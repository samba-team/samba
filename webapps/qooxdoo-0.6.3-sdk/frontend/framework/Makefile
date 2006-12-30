###################################################################################
# VARIABLES
###################################################################################

FRAMEWORK=.
GENERATOR=$(FRAMEWORK)/tool/generator.py
CACHE=$(FRAMEWORK)/.cache
SOURCELOADER=
NICE=10
TIMEFLAG = `date +'%s'`

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

source: generate-source
build: generate-build
debug: generate-debug
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
	@rm -f build/script/qx.js source/script/qx.js

realclean: clean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (REAL)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) rm -rf build source/script
	@nice -n $(NICE) rm -rf debug-tokens debug-tree

distclean: realclean
	@echo
	@echo "  CLEANUP OF GENERATED FILES (DIST)"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Deleting files..."
	@nice -n $(NICE) find tool -name "*.pyc" | xargs rm -f
	@nice -n $(NICE) find . -name "*~" -o -name "*.bak" -o -name "*.old" -o -name "*.compiled" | xargs rm -rf
	@nice -n $(NICE) rm -rf $(CACHE)




###################################################################################
# GENERATOR TARGETS
###################################################################################

generate-all:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --generate-compiled-script \
	  --compiled-script-file build/script/qx.js \
	  --optimize-strings \
	  --optimize-variables \
	  --copy-resources \
	  --resource-input source/resource \
	  --resource-output build/resource \
	  --source-script-path ../class \
	  --generate-source-script $(SOURCELDR) \
	  --source-script-file source/script/qx.js \
	  --cache-directory $(CACHE)

generate-compile:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --generate-compiled-script \
	  --compiled-script-file build/script/qx.js \
	  --optimize-strings \
	  --optimize-variables \
	  --cache-directory $(CACHE)

generate-resource:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --copy-resources \
	  --resource-input source/resource \
	  --resource-output build/resource \
	  --cache-directory $(CACHE)

generate-build:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --generate-compiled-script \
	  --compiled-script-file build/script/qx.js \
	  --optimize-strings \
	  --optimize-variables \
	  --copy-resources \
	  --resource-input source/resource \
	  --resource-output build/resource \
	  --cache-directory $(CACHE)

generate-source:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --source-script-path ../class \
	  --generate-source-script $(SOURCELDR) \
	  --source-script-file source/script/qx.js \
	  --cache-directory $(CACHE)

generate-tree:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --tree-output-directory debug-tree \
	  --store-tree \
	  --cache-directory $(CACHE)

generate-tokens:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --token-output-directory debug-tokens \
	  --store-tokens \
	  --cache-directory $(CACHE)

generate-debug:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --tree-output-directory debug-tree \
	  --token-output-directory debug-tokens \
	  --store-tree \
	  --store-tokens \
	  --cache-directory $(CACHE)

generate-pretty:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --pretty-print \
	  --cache-directory $(CACHE)

generate-fix:
	@chmod u+x $(GENERATOR) && nice -n $(NICE) $(GENERATOR) \
	  --script-input source/class \
	  --fix-source \
	  --cache-directory $(CACHE)

revision-bump:
	@echo
	@echo "  REVISION BUMP"
	@echo "----------------------------------------------------------------------------"
	@echo "  * Updating version file..."
	@tool/modules/tagtool.py source/class/qx/core/Version.js
	@echo "  * Committing to SVN..."
	@svn commit -m 'Revision bump: Online demo update' source/class/qx/core/Version.js
