/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat statistics class
 */
qx.OO.defineClass("swat.module.documentation.Documentation",
                  swat.module.AbstractModule,
function()
{
  swat.module.AbstractModule.call(this);
});


/**
 * Load the documentation data
 *
 * This function is called the first time a module is actually selected to
 * appear.  Creation of the module's GUI has been deferred until it was
 * actually needed (now), so we need to create it.
 *
 * @param module {Object} @see AbstractModule
 */
qx.Proto.initialAppear = function(module)
{
  qx.manager.object.AliasManager.getInstance().add("api", "./resource/image");

  // Include CSS file.
  // (This is the hard way; I can't get qx.dom.StyleSheet.includeFile to load)
  var el = document.createElement("link");
  el.type = "text/css";
  el.rel = "stylesheet";
  el.href = "./resource/css/apiviewer.css";
  var head = document.getElementsByTagName("head")[0];
  head.appendChild(el);

  // avoid redundant naming by api viewer
  qx.Settings.setCustomOfClass("apiviewer.Viewer", "title", ""); 

  var viewer = new api.Viewer();
  module.canvas.add(viewer);
  viewer.load("script/data.js");

  // Replace the existing (temporary) finite state machine with a null one
  swat.module.documentation.Fsm.getInstance().buildFsm(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
