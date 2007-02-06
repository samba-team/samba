/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/*
#embed(apiviewer.css/*)
#embed(apiviewer.image/*)
*/


/**
 * Swat statistics class
 */
qx.OO.defineClass("swat.module.documentation.Documentation",
                  swat.main.AbstractModule,
function()
{
  swat.main.AbstractModule.call(this);
});


/**
 * Load the documentation data
 *
 * This function is called the first time a module is actually selected to
 * appear.  Creation of the module's GUI has been deferred until it was
 * actually needed (now), so we need to create it.
 *
 * @param module {swat.main.Module}
 *   The module descriptor for the module.
 */
qx.Proto.initialAppear = function(module)
{
  // Define alias for custom resource path
  var am = qx.manager.object.AliasManager.getInstance();
  am.add("api", qx.Settings.getValueOfClass("apiviewer", "resourceUri"));

  // Include CSS file
  qx.html.StyleSheet.includeFile(am.resolvePath("api/css/apiviewer.css"));
  am.add("apiviewer", "./resource/image");

  // avoid redundant naming by api viewer
  qx.Settings.setCustomOfClass("apiviewer.Viewer", "title", ""); 

  var viewer = new apiviewer.Viewer();
  module.canvas.add(viewer);
  viewer.load("script/data.js");

  // Replace the existing (temporary) finite state machine with a null one
  swat.module.documentation.Fsm.getInstance().buildFsm(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
