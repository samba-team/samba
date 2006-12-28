/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/*
#require(swat.module.Module)
#require(swat.module.AbstractModule)
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
 * Register our supported modules
 */

//#require(swat.module.statistics.Statistics)
new swat.module.Module("Statistics",
                       swat.module.statistics.Statistics);

//#require(swat.module.documentation.Documentation)
//#require(api.Viewer)
new swat.module.Module("API Documentation",
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
  var moduleList = swat.module.Module.getList();
  for (moduleName in moduleList)
  {
    // ... add the module's name to the module object, ...
    moduleList[moduleName].name = moduleName;

    // ... and call the module's buildInitialFsm() function
    var module = moduleList[moduleName]["class"].getInstance();
    module.buildInitialFsm(moduleList[moduleName]);
  }
};


qx.Proto.main = function()
{
  var moduleList = swat.module.Module.getList();

  // Initialize the gui for the main menu
  swat.main.Gui.buildGui(moduleList);

  // Similarly, now that we have a canvas for each module, ...
  for (moduleName in moduleList)
  {
    // ... call the module's buildInitialGui() function
    var module = moduleList[moduleName]["class"].getInstance();
    module.buildInitialGui(moduleList[moduleName]);
  }
};


qx.Proto.finalize = function()
{
  // Call each module's finalization function
  var moduleList = swat.module.Module.getList();
  for (moduleName in moduleList)
  {
    var module = moduleList[moduleName]["class"].getInstance();
    module.finalize(moduleList[moduleName]);
  }
};

