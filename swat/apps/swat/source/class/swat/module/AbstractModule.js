/**
 * Abstract Module class.  All modules should extend this class.
 */
qx.OO.defineClass("swat.module.AbstractModule", qx.core.Object,
function()
{
  qx.core.Object.call(this);
  this.debug("AbstractModule constructor");
});


/**
 * Build the initial finite state machine.
 *
 * In order to prevent long load times, as minimal as possible of an initial
 * FSM should be created.  The FSM will receive a "visible" event when the
 * module is first selected (and each subsequent time), and the FSM can use
 * that event to build the complete FSM.
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
 *     class -
 *       The class for this module
 *
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
   *  "appear" on swat.module.canvas
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
            "swat.module.canvas" :
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
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_Idle_Load_Gui",
    {
      "nextState" :
        qx.util.fsm.FiniteStateMachine.StateChange.CURRENT_STATE,

      "ontransition" :
        function(fsm, event)
        {
          // Make the "Loading" message go away.  (We need to learn how to
          // remove it entirely.  Just doing canvas.removeAll() leaves
          // something in the widget queue and we get spurious error
          // messages.)
          var children = module.canvas.getVisibleChildren();
          for (var child in children)
          {
            children[child].hide();
          }

          // Call the module's initialAppear function to build FSM and GUI.
          // That function should *replace* this state, State_Idle, to which
          // we'll transition.
          thisModule.initialAppear(module);
        }
    });
  state.addTransition(trans);

  // Save the finite state machine for this module
  module.fsm = fsm;
  fsm.addObject("swat.module.fsm", fsm);
  fsm.start();
};

/**
 * Build the initial graphical user interface.
 *
 * In order to prevent long load times, as minimal as possible of an initial
 * GUI should be created.  Generally, this is just a "Loading..." message.
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
 *     class -
 *       The class for this module
 *
 */
qx.Proto.buildInitialGui = function(module)
{
  // For now, just create the "Loading" text
  var o = new qx.ui.basic.Label("Loading module '" + module.name + "'...");
  o.set({
            top: 12,
            left: 20
        });
  o.setFont("bold");
  module.canvas.add(o);
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
qx.Class.getInstance = qx.util.Return.returnInstance;
