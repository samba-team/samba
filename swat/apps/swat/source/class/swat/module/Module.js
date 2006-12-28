/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * This class defines a module descriptor (the registration of a module) and
 * maintains the list of modules that have been registered.
 */
qx.OO.defineClass("swat.module.Module", qx.core.Object,
function(moduleName, class)
{
  qx.core.Object.call(this);

  // Initialize commonly-used properties of a module
  this.canvas = null;
  this.fsm = null;
  this.gui = null;

  // Save this class name
  this.class = class;

  // Add this new module to the module list.
  swat.module.Module._list[moduleName] = this;
});


/**
 * Return the list of modules
 */
qx.Class.getList = function()
{
  return swat.module.Module._list;
};


/**
 * The list of modules which have been registered.
 */
qx.Class._list = { };
