/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat LDB Browser class
 */
qx.OO.defineClass("swat.module.ldbbrowse.LdbBrowse",
                  swat.module.AbstractModule,
function()
{
  swat.module.AbstractModule.call(this);
});


/**
 * Create the module's finite state machine and graphical user interface.
 *
 * This function is called the first time a module is actually selected to
 * appear.  Creation of the module's actual FSM and GUI have been deferred
 * until they were actually needed (now) so we need to create them.
 *
 * @param module {swat.module.Module}
 *   The module descriptor for the module.
 */
qx.Proto.initialAppear = function(module)
{
  // Initial database to open
  module.dbFile = "sam.ldb";

  // Replace the existing (temporary) finite state machine with the real one
  swat.module.ldbbrowse.Fsm.getInstance().buildFsm(module);

  // Create the real gui
  swat.module.ldbbrowse.Gui.getInstance().buildGui(module);

  // Force the global database to be opened
  var dbName = module.fsm.getObject("dbName");
  dbName.setSelected(dbName.getList().getFirstChild());
  dbName.dispatchEvent(new qx.event.type.Event("changeSelection"), true);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
