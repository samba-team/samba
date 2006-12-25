/**
 * Swat statistics class
 */
qx.OO.defineClass("swat.module.stats.Statistics", swat.module.AbstractModule,
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
 * @param module {Object} @see AbstractModule
 */
qx.Proto.initialAppear = function(module)
{
  // Replace the existing (temporary) finite state machine with the real one
  swat.module.stats.Fsm.getInstance().buildFsm(module);

  // Create the real gui
  swat.module.stats.Gui.getInstance().buildGui(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
