qx.core.Init.getInstance().defineMain(function()
{
  // Initialize the finite state machine
  fsm = initFsm();

  // Initialize the GUI
  initGui(fsm);

  // Start the finite state machine
  fsm.start();
});
