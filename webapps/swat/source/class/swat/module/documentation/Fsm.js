/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat statistics class finite state machine
 */
qx.OO.defineClass("swat.module.documentation.Fsm",
                  swat.main.AbstractModuleFsm,
function()
{
  swat.main.AbstractModuleFsm.call(this);
});


qx.Proto.buildFsm = function(module)
{
  var fsm = module.fsm;

  /*
   * State: Idle
   *
   *   This is a null state to replace the one that loads the API viewer.  The
   *   API viewer does not use the finite state machine.
   */
  var state = new qx.util.fsm.State(
    "State_Idle",
    {
      "events" :
        {
          // We need at least one event listed due to FSM requirements
          "appear" :
          {
            "swat.main.canvas" :
              "Transition_Idle_to_Idle_via_appear"
          }
        }
    });

  // Replace the initial Idle state with this one
  fsm.replaceState(state, true);

  /*
   * Transition: Idle to Idle
   *
   * Cause: "appear" on canvas
   *
   * Action:
   *  None.
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_Idle_via_appear",
    {
      "nextState" :
        "State_Idle"
    });
  state.addTransition(trans);

};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
