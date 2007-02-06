/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/*
#require(swat.main.Module)
#require(swat.main.AbstractModule)
#require(swat.main.Authenticate);
*/

/**
 * Swat main menu
 */
qx.OO.defineClass("swat.main.Main", qx.component.AbstractApplication,
function()
{
  qx.component.AbstractApplication.call(this);
});

/*
 * Register our supported modules.  The order listed here is the order they
 * will appear in the Modules menu.
 */

//#require(swat.module.statistics.Statistics)
new swat.main.Module("Status and Statistics",
                     swat.module.statistics.Statistics);

//#require(swat.module.ldbbrowse.LdbBrowse)
new swat.main.Module("LDB Browser",
                     swat.module.ldbbrowse.LdbBrowse);

//#require(swat.module.documentation.Documentation)
//#require(apiviewer.Viewer)
new swat.main.Module("API Documentation",
                     swat.module.documentation.Documentation);


/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.initialize = function()
{
  // Set the resource URI
  qx.Settings.setCustom("resourceUri", "./resource");

  // Turn on JSON debugging for the time being
  qx.Settings.setCustomOfClass("qx.io.Json", "enableDebug", true);

  // For each module...
  var moduleList = swat.main.Module.getList();
  for (moduleName in moduleList)
  {
    // ... call the module's buildInitialFsm() function
    var module = moduleList[moduleName]["clazz"].getInstance();
    module.buildInitialFsm(moduleList[moduleName]);
  }
};


qx.Proto.main = function()
{
  var moduleList = swat.main.Module.getList();

  // Initialize the gui for the main menu
  swat.main.Gui.buildGui(moduleList);

  // Similarly, now that we have a canvas for each module, ...
  for (moduleName in moduleList)
  {
    // ... call the module's buildInitialGui() function
    var module = moduleList[moduleName]["clazz"].getInstance();
    module.buildInitialGui(moduleList[moduleName]);
  }
};


qx.Proto.finalize = function()
{
  // Call each module's finalization function
  var moduleList = swat.main.Module.getList();
  for (moduleName in moduleList)
  {
    var module = moduleList[moduleName]["clazz"].getInstance();
    module.finalize(moduleList[moduleName]);
  }
};

