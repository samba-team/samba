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
 *
 * A Module object contains the following public properties which may be
 * accessed directly by name:
 *
 *   fsm -
 *     The finite state machine for this module.
 *
 *   canvas -
 *     The canvas on which to create the gui for this module
 *
 *   name -
 *     The name of this module
 *
 *   class -
 *     The class for this module
 *
 * @param moduleName {string}
 *   The name of the module being registered.  This is the name that will
 *   appear in the Modules menu.
 *
 * @param class {class}
 *   The class which contains the module implementation.  That class must
 *   extend swat.module.AbstractModule and implement a singleton interface
 *   that provides a public method called initialAppear() which takes this
 *   Module object as a parameter, and creates the finite state machine for
 *   the module (if applicable) and builds the graphical user interface for
 *   the module.
 */
qx.OO.defineClass("swat.module.Module", qx.core.Object,
function(moduleName, class)
{
  qx.core.Object.call(this);

  // Initialize commonly-used properties of a module
  this.canvas = null;
  this.fsm = null;
  this.gui = null;

  // Save the module name
  this.name = moduleName;

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
