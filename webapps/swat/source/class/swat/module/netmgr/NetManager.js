/*
 * Copyright (C)  Rafal Szczesniak 2007
 */

/**
 * Swat Net Manager class
 */
qx.OO.defineClass("swat.module.netmgr.NetManager",
		  swat.main.AbstractModule,
function()
{
  swat.main.AbstractModule.call(this);
});


qx.Proto.initialAppear = function(module)
{
  // Replace the existing (temporary) finite state machine with the real one
  swat.module.netmgr.Fsm.getInstance().buildFsm(module);

  // Create the real gui
  swat.module.netmgr.Gui.getInstance().buildGui(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
