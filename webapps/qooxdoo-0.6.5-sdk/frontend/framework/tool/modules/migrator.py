#!/usr/bin/env python
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
#
################################################################################

import sys, re, os
import config, filetool, treegenerator, tokenizer, compiler, textutil

def entryCompiler(line):
  # protect escaped equal symbols
  line = line.replace("\=", "----EQUAL----")

  splitLine = line.split("=")

  if len(splitLine) != 2:
    print "        - Malformed entry: %s" % line
    return

  orig = splitLine[0].strip()
  repl = splitLine[1].strip()

  #print "%s :: %s" % (orig, value)

  # recover protected equal symbols
  orig = orig.replace("----EQUAL----", "=")
  repl = repl.replace("----EQUAL----", "=")

  return {"expr":re.compile(orig), "orig":orig, "repl":repl}




def regtool(content, regs, patch, options):
  for patchEntry in regs:
    matches = patchEntry["expr"].findall(content)
    itercontent = content
    line = 1

    for fragment in matches:

      # Replacing
      if patch:
        content = patchEntry["expr"].sub(patchEntry["repl"], content, 1)
        # Debug
        if options.verbose:
          print "      - Replacing pattern '%s' to '%s'" % (patchEntry["orig"], patchEntry["repl"])
          
      else:
        # Search for first match position
        pos = itercontent.find(fragment)
        pos = patchEntry["expr"].search(itercontent).start()
    
        # Update current line
        line += len((itercontent[:pos] + fragment).split("\n")) - 1
    
        # Removing leading part til matching part
        itercontent = itercontent[pos+len(fragment):]
    
        # Debug
        if options.verbose:
          print "      - Matches %s in %s" % (patchEntry["orig"], line)

        print "      - line %s : (%s)" % (line, patchEntry["orig"])
        print "        %s" % patchEntry["repl"]

  return content




def getHtmlList(options):
  htmlList = []

  for htmlDir in options.migrationInput:
    for root, dirs, files in os.walk(htmlDir):

      # Filter ignored directories
      for ignoredDir in config.DIRIGNORE:
        if ignoredDir in dirs:
          dirs.remove(ignoredDir)

      # Searching for files
      for fileName in files:
        if os.path.splitext(fileName)[1] in [ ".js", ".html", ".htm", ".php", ".asp", ".jsp" ]:
          htmlList.append(os.path.join(root, fileName))

  return htmlList



def handle(fileList, fileDb, options):
  confPath = os.path.join(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "migration"), options.migrationTarget)

  infoPath = os.path.join(confPath, "info")
  patchPath = os.path.join(confPath, "patches")

  importedModule = False
  infoList = []
  patchList = []
  htmlList = getHtmlList(options)




  print "  * Number of script input files: %s" % len(fileList)
  print "  * Number of HTML input files: %s" % len(htmlList)
  print "  * Update to version: %s" % options.migrationTarget



  print "  * Searching for patch module..."

  for root, dirs, files in os.walk(confPath):

    # Filter ignored directories
    for ignoredDir in config.DIRIGNORE:
      if ignoredDir in dirs:
        dirs.remove(ignoredDir)

    # Searching for files
    for fileName in files:
      filePath = os.path.join(root, fileName)

      if os.path.splitext(fileName)[1] != config.PYEXT:
        continue

      if fileName == "patch.py":
        print "    - Importing..."

        if not root in sys.path:
          sys.path.insert(0, root)

        import patch
        importedModule = True







  emptyLine = re.compile("^\s*$")



  print "  * Searching for info expression data..."

  for root, dirs, files in os.walk(infoPath):

    # Filter ignored directories
    for ignoredDir in config.DIRIGNORE:
      if ignoredDir in dirs:
        dirs.remove(ignoredDir)

    # Searching for files
    for fileName in files:
      filePath = os.path.join(root, fileName)

      fileContent = textutil.any2Unix(filetool.read(filePath, "utf-8"))
      infoList.append({"path":filePath, "content":fileContent.split("\n")})

      if options.verbose:
        print "    - %s" % filePath

  print "    - Number of info files: %s" % len(infoList)

  print "    - Compiling expressions..."

  compiledInfos = []

  for infoFile in infoList:
    print "      - %s" % os.path.basename(infoFile["path"])
    for line in infoFile["content"]:
      if emptyLine.match(line) or line.startswith("#") or line.startswith("//"):
        continue

      compiled = entryCompiler(line)
      if compiled != None:
        compiledInfos.append(compiled)

  print "    - Number of infos: %s" % len(compiledInfos)




  print "  * Searching for patch expression data..."

  for root, dirs, files in os.walk(patchPath):

    # Filter ignored directories
    for ignoredDir in config.DIRIGNORE:
      if ignoredDir in dirs:
        dirs.remove(ignoredDir)

    # Searching for files
    for fileName in files:
      filePath = os.path.join(root, fileName)

      fileContent = textutil.any2Unix(filetool.read(filePath, "utf-8"))
      patchList.append({"path":filePath, "content":fileContent.split("\n")})

      if options.verbose:
        print "    - %s" % filePath

  print "    - Number of patch files: %s" % len(patchList)

  print "    - Compiling expressions..."

  compiledPatches = []

  for patchFile in patchList:
    print "      - %s" % os.path.basename(patchFile["path"])
    for line in patchFile["content"]:
      if emptyLine.match(line) or line.startswith("#") or line.startswith("//"):
        continue

      compiled = entryCompiler(line)
      if compiled != None:
        compiledPatches.append(compiled)

  print "    - Number of patches: %s" % len(compiledPatches)








  print
  print "  FILE PROCESSING:"
  print "----------------------------------------------------------------------------"

  if len(fileList) > 0:
    print "  * Processing script files:"

    for fileId in fileList:
      fileEntry = fileDb[fileId]

      filePath = fileEntry["path"]
      fileEncoding = fileEntry["encoding"]

      print "    - %s" % fileId

      # Read in original content
      fileContent = filetool.read(filePath, fileEncoding)
      patchedContent = fileContent

      # Apply patches
      if importedModule:
        tree = treegenerator.createSyntaxTree(tokenizer.parseStream(patchedContent))

        # If there were any changes, compile the result
        if patch.patch(fileId, tree):
          patchedContent = compiler.compile(tree, True)

      patchedContent = regtool(patchedContent, compiledPatches, True, options)
      patchedContent = regtool(patchedContent, compiledInfos, False, options)

      # Write file
      if patchedContent != fileContent:
        print "      - Store modifications..."
        filetool.save(filePath, patchedContent, fileEncoding)

    print "  * Done"



  if len(htmlList) > 0:
    print "  * Processing HTML files:"

    for filePath in htmlList:
      print "    - %s" % filePath

      # Read in original content
      fileContent = filetool.read(filePath)

      patchedContent = fileContent
      patchedContent = regtool(patchedContent, compiledPatches, True, options)
      patchedContent = regtool(patchedContent, compiledInfos, False, options)

      # Write file
      if patchedContent != fileContent:
        print "      - Store modifications..."
        filetool.save(filePath, patchedContent)

    print "  * Done"











######################################################################
#  MAIN LOOP
######################################################################

if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    print
    print "  * Keyboard Interrupt"
    sys.exit(1)
