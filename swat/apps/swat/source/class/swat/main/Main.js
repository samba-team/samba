/*
#module(swat_main)
#require(swat.module.AbstractModule)
#require(swat.module.stats.Statistics)
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
var moduleSystemStatus =
{
  "canvas" : null,
  "fsm"    : null,
  "class"  : swat.module.stats.Statistics
};

/*
var moduleLdbView =
{
  "canvas" : null,
  "fsm"    : null,
  "class"  : swat.module.ldbview.LdbView
};
*/

qx.Class.modules =
{
  list :
  {
    "System Status" : moduleSystemStatus
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
  var o = new qx.ui.basic.Label("hello world");

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
}
