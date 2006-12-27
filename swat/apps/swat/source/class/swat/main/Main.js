/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/*
#require(swat.module.AbstractModule)
#require(swat.module.statistics.Statistics)
#require(swat.module.documentation.Documentation)
#require(api.Viewer)
*/

/**
 * Swat main menu
 */
qx.OO.defineClass("swat.main.Main", qx.component.AbstractApplication,
function()
{
  qx.component.AbstractApplication.call(this);
});

/**
 * The list of supported modules
 */
qx.Class.modules =
{
  list :
  {
    "System Status" :
    {
      "canvas" : null,
      "fsm"    : null,
      "gui"    : null,
      "class"  : swat.module.statistics.Statistics
    },
    "Documentation" :
    {
      "canvas" : null,
      "fsm"    : null,
      "gui"    : null,
      "class"  : swat.module.documentation.Documentation
    }
  }
};


/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.initialize = function()
{
  var modules = swat.main.Main.modules;

  // Set the resource URI
  qx.Settings.setCustom("resourceUri", "./resource");

  // Turn on JSON debugging for the time being
  qx.Settings.setCustomOfClass("qx.io.Json", "enableDebug", true);

  // For each module...
  for (moduleName in modules.list)
  {
    // ... add the module's name to the module object, ...
    modules.list[moduleName].name = moduleName;

    // ... and call the module's buildInitialFsm() function
    var module = modules.list[moduleName]["class"].getInstance();
    module.buildInitialFsm(modules.list[moduleName]);
  }
};


qx.Proto.main = function()
{
  var modules = swat.main.Main.modules;

  // Initialize the gui for the main menu
  swat.main.Gui.buildGui(modules);

  // Similarly, now that we have a canvas for each module, ...
  for (moduleName in modules.list)
  {
    // ... call the module's buildInitialGui() function
    var module = modules.list[moduleName]["class"].getInstance();
    module.buildInitialGui(modules.list[moduleName]);
  }
};


qx.Proto.finalize = function()
{
  var modules = swat.main.Main.modules;

  // Call each module's finalization function
  for (moduleName in modules.list)
  {
    var module = modules.list[moduleName]["class"].getInstance();
    module.finalize(modules.list[moduleName]);
  }
};

