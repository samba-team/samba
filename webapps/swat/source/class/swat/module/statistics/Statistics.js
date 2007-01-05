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
qx.OO.defineClass("swat.module.statistics.Statistics",
                  swat.main.AbstractModule,
function()
{
  swat.main.AbstractModule.call(this);
});


/**
 * Create the module's finite state machine and graphical user interface.
 *
 * This function is called the first time a module is actually selected to
 * appear.  Creation of the module's actual FSM and GUI have been deferred
 * until they were actually needed (now) so we need to create them.
 *
 * @param module {swat.main.Module}
 *   The module descriptor for the module.
 */
qx.Proto.initialAppear = function(module)
{
  // Replace the existing (temporary) finite state machine with the real one
  swat.module.statistics.Fsm.getInstance().buildFsm(module);

  // Create the real gui
  swat.module.statistics.Gui.getInstance().buildGui(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
