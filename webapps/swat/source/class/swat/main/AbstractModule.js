/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Abstract Module class.  All modules should extend this class.
 */
qx.OO.defineClass("swat.main.AbstractModule", qx.core.Object,
function()
{
  qx.core.Object.call(this);
  this.debug("AbstractModule constructor");
});


/**
 * Build the initial finite state machine.
 *
 * In order to prevent long load times, as minimal as possible of an initial
 * FSM should be created.  The FSM will receive an "appear" event when the
 * module is first selected (and each subsequent time), and the FSM can use
 * that event to build the complete FSM.
 *
 * @param module {swat.main.Module}
 *    The module descriptor for the module.
 */
qx.Proto.buildInitialFsm = function(module)
{
  // Create a new finite state machine
  var fsm = new qx.util.fsm.FiniteStateMachine(module.name);

  // For this simple example application, show all debug messages.
  qx.Settings.setCustomOfClass(
    "qx.util.fsm.FiniteStateMachine",
    "debugFlags",
    (qx.util.fsm.FiniteStateMachine.DebugFlags.EVENTS |
     qx.util.fsm.FiniteStateMachine.DebugFlags.TRANSITIONS |
     qx.util.fsm.FiniteStateMachine.DebugFlags.FUNCTION_DETAIL |
     qx.util.fsm.FiniteStateMachine.DebugFlags.OBJECT_NOT_FOUND));

  /*
   * State: Idle
   *
   * Transition on:
   *  "appear" on swat.main.canvas
   */
  var state = new qx.util.fsm.State(
    "State_Idle",
    {
      "events" :
        {
          // When we get an appear event the first time, run the transition
          // that will load the module's finite state machine and graphical
          // user interface.
          "appear"  :
          {
            "swat.main.canvas" :
              "Transition_Idle_to_Idle_Load_Gui"
          }
        }
    });
  fsm.addState(state);

  /*
   * Transition: Idle to (replaced) Idle
   *
   * Cause: "appear" on canvas for the first time
   *
   * Action:
   *  Load module's finite state machine and graphical user interface
   */
  var thisModule = this;
  var newModule = module;
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_Idle_Load_Gui",
    {
      "nextState" :
        qx.util.fsm.FiniteStateMachine.StateChange.CURRENT_STATE,

      "ontransition" :
        function(fsm, event)
        {
          // Call the module's initialAppear function to build FSM and GUI.
          // That function should *replace* this state, State_Idle, to which
          // we'll transition.
          var canvas = fsm.getObject("swat.main.canvas");
          canvas.getTopLevelWidget().setGlobalCursor("progress");
          if (! newModule.bLoaded)
          {
            window.setTimeout(
              function()
              {
                // Call the module's initial appear handler
                thisModule.initialAppear(newModule);

                // Regenerate the appear event, since the original one got
                // lost by doing this code inside of the timeout.
                canvas.createDispatchEvent("appear");

                // Reset the cursor to the default
                canvas.getTopLevelWidget().setGlobalCursor(null);

              }, 0);
            newModule.bLoaded = true;
          }
        }
    });
  state.addTransition(trans);

  // Save the finite state machine for this module
  module.fsm = fsm;

  // Save the module descriptor in the finite state machine
  fsm.addObject("swat.main.module", module);

  // Create an RPC object for use by this module
  module.rpc = new qx.io.remote.Rpc();
  module.rpc.setUrl("/services/");
  module.rpc.setTimeout(10000);
  module.rpc.setCrossDomain(false);
  module.rpc.addEventListener("completed", fsm.eventListener, fsm);
  module.rpc.addEventListener("failed", fsm.eventListener, fsm);
  module.rpc.addEventListener("timeout", fsm.eventListener, fsm);
  module.rpc.addEventListener("aborted", fsm.eventListener, fsm);
  fsm.addObject("swat.main.rpc", module.rpc);

  // Start the finite state machine
  fsm.start();
};

/**
 * Build the initial graphical user interface.
 *
 * Generally, this is a no-op.
 *
 * @param module {Object}
 *   An object containing at least the following properties:
 *     fsm -
 *       The finite state machine for this module.  It should be filled in
 *       by this function.
 *     canvas -
 *       The canvas on which to create the gui for this module
 *     name -
 *       The name of this module
 *     clazz -
 *       The class for this module
 *
 */
qx.Proto.buildInitialGui = function(module)
{
  // nothing to do
};

qx.Proto.finalize = function(module)
{
  this.debug("AbstractModule.finalize()");
};


/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
