#!/usr/bin/env python

import sys, string, re, os, random, cPickle, codecs
import config, tokenizer, treegenerator, filetool, stringoptimizer

internalModTime = 0


def validateFiles():

  global internalModTime

  base = os.path.dirname(os.path.abspath(sys.argv[0]))
  if base.endswith("modules"):
    path = base
  else:
    path = os.path.join(base, "modules")

  maxFileModTime = os.stat(os.path.join(path, ".." + os.path.sep + "generator.py")).st_mtime

  for root, dirs, files in os.walk(path):

    # Filter ignored directories
    for ignoredDir in config.DIRIGNORE:
      if ignoredDir in dirs:
        dirs.remove(ignoredDir)

    # Searching for files
    for fileName in files:
      if os.path.splitext(fileName)[1] != config.PYEXT:
        continue

      filePath = os.path.join(root, fileName)
      fileModTime = os.stat(filePath).st_mtime

      if fileModTime > maxFileModTime:
        maxFileModTime = fileModTime


  internalModTime = maxFileModTime



def getInternalModTime(options):

  global internalModTime

  if internalModTime == 0 and not options.disableInternalCheck:
    validateFiles()

  return internalModTime



def extractFileContentId(data):
  for item in config.QXHEAD["id"].findall(data):
    return item

  for item in config.QXHEAD["classDefine"].findall(data):
    return item

  # TODO: Obsolete with 0.7
  for item in config.QXHEAD["defineClass"].findall(data):
    return item[0]

  return None


def extractSuperClass(data):
  for item in config.QXHEAD["superClass"].findall(data):
    return item

  # TODO: Obsolete with 0.7
  for item in config.QXHEAD["defineClass"].findall(data):
    return item[2]

  return None


def extractLoadtimeDeps(data, fileId=""):
  deps = []

  # qooxdoo specific:
  # store inheritance deps
  superClass = extractSuperClass(data)
  if superClass != None and superClass != "" and not superClass in config.JSBUILTIN:
    deps.append("qx.OO")
    deps.append(superClass)
  elif "qx.OO.defineClass(" in data:
    deps.append("qx.OO")


  # Adding explicit requirements
  for item in config.QXHEAD["require"].findall(data):
    if item == fileId:
      print "      - Self-referring load dependency: %s" % item
    elif item in deps:
      print "      - Double definition of load dependency: %s" % item
    else:
      deps.append(item)

  return deps


def extractAfterDeps(data, fileId=""):
  deps = []

  # Adding explicit after requirements
  for item in config.QXHEAD["after"].findall(data):
    if item == fileId:
      print "      - Self-referring load dependency: %s" % item
    elif item in deps:
      print "      - Double definition of load dependency: %s" % item
    else:
      deps.append(item)

  return deps


def extractRuntimeDeps(data, fileId=""):
  deps = []

  # Adding explicit runtime requirements
  for item in config.QXHEAD["use"].findall(data):
    if item == fileId:
      print "      - Self-referring runtime dependency: %s" % item
    elif item in deps:
      print "      - Double definition of runtime dependency: %s" % item
    else:
      deps.append(item)

  return deps


def extractLoadDeps(data, fileId=""):
  deps = []

  # Adding before requirements
  for item in config.QXHEAD["load"].findall(data):
    if item == fileId:
      print "      - Self-referring runtime dependency: %s" % item
    elif item in deps:
      print "      - Double definition of runtime dependency: %s" % item
    else:
      deps.append(item)

  return deps


def extractOptional(data):
  deps = []

  # Adding explicit requirements
  for item in config.QXHEAD["optional"].findall(data):
    if not item in deps:
      deps.append(item)

  return deps


def extractModules(data):
  mods = []

  for item in config.QXHEAD["module"].findall(data):
    if not item in mods:
      mods.append(item)

  return mods


def extractResources(data):
  res = []

  for item in config.QXHEAD["resource"].findall(data):
    res.append(item)

  return res






def getTokens(fileDb, fileId, options):
  if not fileDb[fileId].has_key("tokens"):
    if options.verbose:
      print "    - Generating tokens for %s..." % fileId

    useCache = False
    loadCache = False

    fileEntry = fileDb[fileId]

    filePath = fileEntry["path"]
    fileEncoding = fileEntry["encoding"]

    if options.cacheDirectory != None:
      cachePath = os.path.join(filetool.normalize(options.cacheDirectory), fileId + "-tokens.pcl")
      useCache = True

      if not filetool.checkCache(filePath, cachePath, getInternalModTime(options)):
        loadCache = True

    if loadCache:
      tokens = filetool.readCache(cachePath)
    else:
      fileContent = filetool.read(filePath, fileEncoding)
      tokens = tokenizer.parseStream(fileContent, fileId)

      if useCache:
        if options.verbose:
          print "    - Caching tokens for %s..." % fileId

        filetool.storeCache(cachePath, tokens)

    fileDb[fileId]["tokens"] = tokens

  return fileDb[fileId]["tokens"]




def getTree(fileDb, fileId, options):
  if not fileDb[fileId].has_key("tree"):
    if options.verbose:
      print "    - Generating tree for %s..." % fileId

    useCache = False
    loadCache = False

    fileEntry = fileDb[fileId]
    filePath = fileEntry["path"]

    if options.cacheDirectory != None:
      cachePath = os.path.join(filetool.normalize(options.cacheDirectory), fileId + "-tree.pcl")
      useCache = True

      if not filetool.checkCache(filePath, cachePath, getInternalModTime(options)):
        loadCache = True

    if loadCache:
      tree = filetool.readCache(cachePath)
    else:
      tree = treegenerator.createSyntaxTree(getTokens(fileDb, fileId, options))

      if useCache:
        if options.verbose:
          print "    - Caching tree for %s..." % fileId

        filetool.storeCache(cachePath, tree)

    fileDb[fileId]["tree"] = tree

  return fileDb[fileId]["tree"]





def getStrings(fileDb, fileId, options):
  if not fileDb[fileId].has_key("strings"):
    if options.verbose:
      print "    - Searching for strings in %s..." % fileId

    useCache = False
    loadCache = False

    fileEntry = fileDb[fileId]
    filePath = fileEntry["path"]

    if options.cacheDirectory != None:
      cachePath = os.path.join(filetool.normalize(options.cacheDirectory), fileId + "-strings.pcl")
      useCache = True

      if not filetool.checkCache(filePath, cachePath, getInternalModTime(options)):
        loadCache = True

    if loadCache:
      strings = filetool.readCache(cachePath)
    else:
      strings = stringoptimizer.search(getTree(fileDb, fileId, options), options.verbose)

      if useCache:
        if options.verbose:
          print "    - Caching strings for %s..." % fileId

        filetool.storeCache(cachePath, strings)

    fileDb[fileId]["strings"] = strings

  return fileDb[fileId]["strings"]





def resolveAutoDeps(fileDb, options):
  ######################################################################
  #  DETECTION OF AUTO DEPENDENCIES
  ######################################################################

  if options.verbose:
    print "  * Resolving dependencies..."
  else:
    print "  * Resolving dependencies: ",

  knownIds = []
  depCounter = 0
  hasMessage = False

  for fileId in fileDb:
    knownIds.append(fileId)

  for fileId in fileDb:
    fileEntry = fileDb[fileId]

    if fileEntry["autoDeps"] == True:
      continue

    if not options.verbose:
      sys.stdout.write(".")
      sys.stdout.flush()

    hasMessage = False

    fileTokens = getTokens(fileDb, fileId, options)
    fileDeps = []

    assembledName = ""

    for token in fileTokens:
      if token["type"] == "name" or token["type"] == "builtin":
        if assembledName == "":
          assembledName = token["source"]
        else:
          assembledName += ".%s" % token["source"]

        if assembledName in knownIds:
          if assembledName != fileId and not assembledName in fileDeps:
            fileDeps.append(assembledName)

          assembledName = ""

      elif not (token["type"] == "token" and token["source"] == "."):
        if assembledName != "":
          assembledName = ""

        if token["type"] == "string" and token["source"] in knownIds and token["source"] != fileId and not token["source"] in fileDeps:
          fileDeps.append(token["source"])


    if options.verbose:
      print "    - Analysing %s..." % fileId

    # Updating lists...
    optionalDeps = fileEntry["optionalDeps"]
    loadtimeDeps = fileEntry["loadtimeDeps"]
    runtimeDeps = fileEntry["runtimeDeps"]

    # Removing optional deps from list
    for dep in optionalDeps:
      if dep in fileDeps:
        fileDeps.remove(dep)

    if options.verbose:

      # Checking loadtime dependencies
      for dep in loadtimeDeps:
        if not dep in fileDeps:
          print "    - Could not confirm #require(%s) in %s!" % (dep, fileId)

      # Checking runtime dependencies
      for dep in runtimeDeps:
        if not dep in fileDeps:
          print "    - Could not confirm #use(%s) in %s!" % (dep, fileId)

    # Adding new content to runtime dependencies
    for dep in fileDeps:
      if not dep in runtimeDeps and not dep in loadtimeDeps:
        if options.verbose:
          print "      - Adding dependency: %s" % dep

        runtimeDeps.append(dep)
        depCounter += 1

    # store flag to omit it the next run
    fileEntry["autoDeps"] = True

  if not hasMessage and not options.verbose:
    print

  print "  * Added %s dependencies" % depCounter




def storeEntryCache(fileDb, options):
  print "  * Storing file entries..."

  cacheCounter = 0
  ignoreDbEntries = [ "tokens", "tree", "path", "pathId", "encoding", "resourceInput", "resourceOutput", "sourceScriptPath", "listIndex", "scriptInput" ]

  for fileId in fileDb:
    fileEntry = fileDb[fileId]

    if fileEntry["cached"] == True:
      continue

    # Store flag
    fileEntry["cached"] = True

    # Copy entries
    fileEntryCopy = {}
    for key in fileEntry:
      if not key in ignoreDbEntries:
        fileEntryCopy[key] = fileEntry[key]

    filetool.storeCache(fileEntry["cachePath"], fileEntryCopy)
    cacheCounter += 1

  print "  * Updated %s files" % cacheCounter




def indexFile(filePath, filePathId, scriptInput, listIndex, scriptEncoding, sourceScriptPath, resourceInput, resourceOutput, options, fileDb={}, moduleDb={}):

  ########################################
  # Checking cache
  ########################################

  useCache = False
  loadCache = False
  cachePath = None

  if options.cacheDirectory != None:
    cachePath = os.path.join(filetool.normalize(options.cacheDirectory), filePathId + "-entry.pcl")
    useCache = True

    if not filetool.checkCache(filePath, cachePath, getInternalModTime(options)):
      loadCache = True



  ########################################
  # Loading file content / cache
  ########################################

  if loadCache:
    fileEntry = filetool.readCache(cachePath)
    fileId = filePathId

  else:
    fileContent = filetool.read(filePath, scriptEncoding)

    # Extract ID
    fileContentId = extractFileContentId(fileContent)

    # Search for valid ID
    if fileContentId == None:
      print "    - Could not extract ID from file: %s. Using fileName!" % filePath
      fileId = filePathId

    else:
      fileId = fileContentId

    if fileId != filePathId:
      print "    - ID mismatch: CONTENT=%s != PATH=%s" % (fileContentId, filePathId)
      sys.exit(1)

    fileEntry = {
      "autoDeps" : False,
      "cached" : False,
      "cachePath" : cachePath,
      "optionalDeps" : extractOptional(fileContent),
      "loadtimeDeps" : extractLoadtimeDeps(fileContent, fileId),
      "runtimeDeps" : extractRuntimeDeps(fileContent, fileId),
      "afterDeps" : extractAfterDeps(fileContent, fileId),
      "loadDeps" : extractLoadDeps(fileContent, fileId),
      "resources" : extractResources(fileContent),
      "modules" : extractModules(fileContent)
    }



  ########################################
  # Additional data
  ########################################

  # We don't want to cache these items
  fileEntry["path"] = filePath
  fileEntry["pathId"] = filePathId
  fileEntry["encoding"] = scriptEncoding
  fileEntry["resourceInput"] = resourceInput
  fileEntry["resourceOutput"] = resourceOutput
  fileEntry["sourceScriptPath"] = sourceScriptPath
  fileEntry["listIndex"] = listIndex
  fileEntry["scriptInput"] = scriptInput


  ########################################
  # Registering file
  ########################################

  # Register to file database
  fileDb[fileId] = fileEntry

  # Register to module database
  for moduleId in fileEntry["modules"]:
    if moduleDb.has_key(moduleId):
      moduleDb[moduleId].append(fileId)
    else:
      moduleDb[moduleId] = [ fileId ]





def indexSingleScriptInput(scriptInput, listIndex, options, fileDb={}, moduleDb={}):
  scriptInput = filetool.normalize(scriptInput)

  # Search for other indexed lists
  if len(options.scriptEncoding) > listIndex:
    scriptEncoding = options.scriptEncoding[listIndex]
  else:
    scriptEncoding = "utf-8"

  if len(options.sourceScriptPath) > listIndex:
    sourceScriptPath = options.sourceScriptPath[listIndex]
  else:
    sourceScriptPath = None

  if len(options.resourceInput) > listIndex:
    resourceInput = options.resourceInput[listIndex]
  else:
    resourceInput = None

  if len(options.resourceOutput) > listIndex:
    resourceOutput = options.resourceOutput[listIndex]
  else:
    resourceOutput = None

  for root, dirs, files in os.walk(scriptInput):

    # Filter ignored directories
    for ignoredDir in config.DIRIGNORE:
      if ignoredDir in dirs:
        dirs.remove(ignoredDir)

    # Searching for files
    for fileName in files:
      if os.path.splitext(fileName)[1] == config.JSEXT:
        filePath = os.path.join(root, fileName)
        filePathId = filePath.replace(scriptInput + os.sep, "").replace(config.JSEXT, "").replace(os.sep, ".")

        indexFile(filePath, filePathId, scriptInput, listIndex, scriptEncoding, sourceScriptPath, resourceInput, resourceOutput, options, fileDb, moduleDb)


def indexScriptInput(options):
  if options.cacheDirectory != None:
    filetool.directory(options.cacheDirectory)

  print "  * Indexing files... "

  fileDb = {}
  moduleDb = {}
  listIndex = 0

  for scriptInput in options.scriptInput:
    indexSingleScriptInput(scriptInput, listIndex, options, fileDb, moduleDb)
    listIndex += 1

  print "  * %s files were found" % len(fileDb)

  if options.enableAutoDependencies:
    resolveAutoDeps(fileDb, options)

  if options.cacheDirectory != None:
    storeEntryCache(fileDb, options)

  return fileDb, moduleDb





"""
Simple resolver, just try to add items and put missing stuff around
the new one.
"""
def addIdWithDepsToSortedList(sortedList, fileDb, fileId):
  if not fileDb.has_key(fileId):
    print "    * Error: Couldn't find required file: %s" % fileId
    return False

  # Test if already in
  if not fileId in sortedList:

    # Including loadtime dependencies
    for loadtimeDepId in fileDb[fileId]["loadtimeDeps"]:
      if loadtimeDepId == fileId: break;
      addIdWithDepsToSortedList(sortedList, fileDb, loadtimeDepId)

    # Including after dependencies
    for afterDepId in fileDb[fileId]["afterDeps"]:
      if afterDepId == fileId: break;
      addIdWithDepsToSortedList(sortedList, fileDb, afterDepId)

    # Add myself
    if not fileId in sortedList:
      sortedList.append(fileId)

    # Include runtime dependencies
    for runtimeDepId in fileDb[fileId]["runtimeDeps"]:
      addIdWithDepsToSortedList(sortedList, fileDb, runtimeDepId)

    # Include load dependencies
    for loadDepId in fileDb[fileId]["loadDeps"]:
      addIdWithDepsToSortedList(sortedList, fileDb, loadDepId)





"""
Search for dependencies, but don't add them. Just use them to put
the new class after the stuff which is required (if it's included, too)
"""
def addIdWithoutDepsToSortedList(sortedList, fileDb, fileId):
  if not fileDb.has_key(fileId):
    print "    * Error: Couldn't find required file: %s" % fileId
    return False

  # Test if already in
  if not fileId in sortedList:

    # Search sortedList for files which needs this one and are already included
    lowestIndex = None
    currentIndex = 0
    for lowId in sortedList:
      for lowDepId in getResursiveLoadDeps([], fileDb, lowId, lowId):
        if lowDepId == fileId and (lowestIndex == None or currentIndex < lowestIndex):
          lowestIndex = currentIndex

      currentIndex += 1

    # Insert at defined index or just append new entry
    if lowestIndex != None:
      sortedList.insert(lowestIndex, fileId)
    else:
      sortedList.append(fileId)




def getResursiveLoadDeps(deps, fileDb, fileId, ignoreId=None):
  if fileId in deps:
    return

  if fileId != ignoreId:
    deps.append(fileId)

  # Including loadtime dependencies
  for loadtimeDepId in fileDb[fileId]["loadtimeDeps"]:
    getResursiveLoadDeps(deps, fileDb, loadtimeDepId)

  # Including after dependencies
  for afterDepId in fileDb[fileId]["afterDeps"]:
    getResursiveLoadDeps(deps, fileDb, afterDepId)

  return deps





def getSortedList(options, fileDb, moduleDb):
  includeWithDeps = []
  excludeWithDeps = []
  includeWithoutDeps = []
  excludeWithoutDeps = []

  sortedIncludeList = []
  sortedExcludeList = []



  # INCLUDE

  # Add Modules and Files (with deps)
  if options.includeWithDeps:
    for include in options.includeWithDeps:
      if include in moduleDb:
        includeWithDeps.extend(moduleDb[include])

      elif "*" in include or "?" in include:
        regstr = "^(" + include.replace('.', '\\.').replace('*', '.*').replace('?', '.?') + ")$"
        regexp = re.compile(regstr)

        for fileId in fileDb:
          if regexp.search(fileId):
            if not fileId in includeWithDeps:
              includeWithDeps.append(fileId)

      else:
        if not include in includeWithDeps:
          includeWithDeps.append(include)


  # Add Modules and Files (without deps)
  if options.includeWithoutDeps:
    for include in options.includeWithoutDeps:
      if include in moduleDb:
        includeWithoutDeps.extend(moduleDb[include])

      elif "*" in include or "?" in include:
        regstr = "^(" + include.replace('.', '\\.').replace('*', '.*').replace('?', '.?') + ")$"
        regexp = re.compile(regstr)

        for fileId in fileDb:
          if regexp.search(fileId):
            if not fileId in includeWithoutDeps:
              includeWithoutDeps.append(fileId)

      else:
        if not include in includeWithoutDeps:
          includeWithoutDeps.append(include)






  # Add all if both lists are empty
  if len(includeWithDeps) == 0 and len(includeWithoutDeps) == 0:
    for fileId in fileDb:
      includeWithDeps.append(fileId)

  # Sorting include (with deps)
  for fileId in includeWithDeps:
    addIdWithDepsToSortedList(sortedIncludeList, fileDb, fileId)

  # Sorting include (without deps)
  for fileId in includeWithoutDeps:
    addIdWithoutDepsToSortedList(sortedIncludeList, fileDb, fileId)



  # EXCLUDE

  # Add Modules and Files (with deps)
  if options.excludeWithDeps:
    for exclude in options.excludeWithDeps:
      if exclude in moduleDb:
        excludeWithDeps.extend(moduleDb[exclude])

      elif "*" in exclude or "?" in exclude:
        regstr = "^(" + exclude.replace('.', '\\.').replace('*', '.*').replace('?', '.?') + ")$"
        regexp = re.compile(regstr)

        for fileId in fileDb:
          if regexp.search(fileId):
            if not fileId in excludeWithDeps:
              excludeWithDeps.append(fileId)

      else:
        if not exclude in excludeWithDeps:
          excludeWithDeps.append(exclude)


  # Add Modules and Files (without deps)
  if options.excludeWithoutDeps:
    for exclude in options.excludeWithoutDeps:
      if exclude in moduleDb:
        excludeWithoutDeps.extend(moduleDb[exclude])

      elif "*" in exclude or "?" in exclude:
        regstr = "^(" + exclude.replace('.', '\\.').replace('*', '.*').replace('?', '.?') + ")$"
        regexp = re.compile(regstr)

        for fileId in fileDb:
          if regexp.search(fileId):
            if not fileId in excludeWithDeps:
              excludeWithoutDeps.append(fileId)

      else:
        if not exclude in excludeWithDeps:
          excludeWithoutDeps.append(exclude)





  # Sorting exclude (with deps)
  for fileId in excludeWithDeps:
    addIdWithDepsToSortedList(sortedExcludeList, fileDb, fileId)

  # Sorting exclude (without deps)
  for fileId in excludeWithoutDeps:
    addIdWithoutDepsToSortedList(sortedExcludeList, fileDb, fileId)




  # MERGE

  # Remove excluded files from included files list
  for fileId in sortedExcludeList:
    if fileId in sortedIncludeList:
      sortedIncludeList.remove(fileId)



  # RETURN

  return sortedIncludeList
