/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by Derrell Lipman

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(util_fsm)
#require(qx.util.fsm.FiniteStateMachine)

************************************************************************ */

/**
 * Create a new possible transition from one state to another.
 *
 * *EXPERIMENTAL*
 * The interface to the finite state machine, states, and transitions is
 * experimental.  It may change in non-backward-compatible ways as more
 * experience is gained in its use.
 *
 * @param transitionName {string}
 *   The name of this transition, used in debug messages.
 *
 * @param transitionInfo {Object}
 *   An object optionally containing any of the following properties:
 *
 *     predicate -
 *       A function which is called to determine whether this transition is
 *       acceptable.  An acceptable transition will cause the transition's
 *       "ontransition" function to be run, the current state's "onexit"
 *       function to be run, and the new state's "onentry" function to be run.
 *
 *       The predicate function's signature is function(fsm, event) and it is
 *       saved in the predicate property of the transition object.  In the
 *       predicate function:
 *
 *         fsm -
 *           The finite state machine object to which this state is attached.
 *
 *         event -
 *           The event that caused a run of the finite state machine
 *
 *       The predicate function should return one of the following three
 *       values:
 *
 *         - true means the transition is acceptable
 *
 *         - false means the transition is not acceptable, and the next
 *           transition (if one exists) should be tried to determine if it is
 *           acceptable
 *
 *         - null means that the transition determined that no further
 *           transitions should be tried.  This might be used when the
 *           transition ascertained that the event is for a target that is not
 *           available in the current state, and the event has called
 *           fsm.queueEvent() to have the event delivered upon state
 *           transition.
 *
 *       It is possible to create a default predicate -- one that will cause a
 *       transition to be acceptable always -- by either not providing a
 *       predicate property, or by explicitely either setting the predicate
 *       property to 'true' or setting it to a function that unconditionally
 *       returns 'true'.  This default transition should, of course, always be
 *       the last transition added to a state, since no transition added after
 *       it will ever be tried.
 *
 *     nextState -
 *       The state to which we transition, if the predicate returns true
 *       (meaning the transition is acceptable).  The value of nextState may
 *       be:
 *
 *         - a string, the state name of the state to transition to
 *
 *         - One of the constants:
 *           - qx.util.fsm.FiniteStateMachine.StateChange.CURRENT_STATE:
 *               Remain in whatever is the current state
 *           - qx.util.fsm.FiniteStateMachine.StateChange.POP_STATE_STACK:
 *               Transition to the state at the top of the saved-state stack,
 *               and remove the top element from the saved-state stack.
 *               Elements are added to the saved-state stack using
 *               fsm.pushState().  It is an error if no state exists on the
 *               saved-state stack.
 *           - qx.util.fsm.FiniteStateMachine.StateChange.TERMINATE:
 *               TBD
 *
 *     autoActionsBeforeOntransition -
 *     autoActionsAfterOntransition -
 *       Automatic actions which take place at the time specified by the
 *       property name.  In all cases, the action takes place immediately
 *       before or after the specified function.
 *
 *       The property value for each of these properties is an object which
 *       describes some number of functions to invoke on a set of specified
 *       objects (typically widgets).
 *
 *       See {@see qx.util.fsm.State} for an example of autoActions.
 *
 *     ontransition -
 *       A function which is called if the predicate function for this
 *       transition returns true.  Its signature is function(fsm, event) and
 *       it is saved in the ontransition property of the transition object.
 *       In the ontransition function:
 *
 *         fsm -
 *           The finite state machine object to which this state is attached.
 *
 *         event -
 *           The event that caused a run of the finite state machine
 *
 *     Additional properties may be provided in transInfo.  They will not be
 *     used by the finite state machine, but will be available via
 *     this.getUserData("<propertyName>") during the transition's predicate
 *     and ontransition functions.
 */
qx.OO.defineClass("qx.util.fsm.Transition", qx.core.Object,
function(transitionName, transitionInfo)
{
  // Call our superclass' constructor
  qx.core.Object.call(this, true);

  // Save the state name
  this.setName(transitionName);

  // Save data from the transitionInfo object
  for (var field in transitionInfo)
  {
    // If we find one of our properties, call its setter.
    switch(field)
    {
    case "predicate":
      this.setPredicate(transitionInfo[field]);
      break;

    case "nextState":
      this.setNextState(transitionInfo[field]);
      break;

    case "autoActionsBeforeOntransition":
      this.setAutoActionsBeforeOntransition(transitionInfo[field]);
      break;

    case "autoActionsAfterOntransition":
      this.setAutoActionsAfterOntransition(transitionInfo[field]);
      break;

    case "ontransition":
      this.setOntransition(transitionInfo[field]);
      break;

    default:
      // Anything else is user-provided data for their own use.  Save it.
      this.setUserData(field, transitionInfo[field]);

      // Log it in case it was a typo and they intended a built-in field
      this.debug("Transition " + transitionName + ": " +
                 "Adding user-provided field to transition: " + field);

      break;
    }
  }
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/**
 * The name of this transition
 */
qx.OO.addProperty(
  {
    name         : "name",
    type         : "string"
  });

/**
 * The predicate function for this transition.  This is documented in the
 * constructor, and is typically provided through the constructor's
 * transitionInfo object, but it is also possible (but highly NOT recommended)
 * to change this dynamically.
 */
qx.OO.addProperty(
  {
    name         : "predicate",
    defaultValue : function(fsm, event) { return true; }
  });

/**
 * The state to transition to, if the predicate determines that this
 * transition is acceptable.  This is documented in the constructor, and is
 * typically provided through the constructor's transitionInfo object, but it
 * is also possible (but highly NOT recommended) to change this dynamically.
 */
qx.OO.addProperty(
  {
    name         : "nextState",
    defaultValue : qx.util.fsm.FiniteStateMachine.StateChange.CURRENT_STATE
  });

/**
 * Automatic actions to take prior to calling the transition's ontransition
 * function.  This is documented in the constructor, and is typically provided
 * through the constructor's transitionInfo object, but it is also possible
 * (but highly NOT recommended) to change this dynamically.
 */
qx.OO.addProperty(
  {
    name         : "autoActionsBeforeOntransition",
    defaultValue : function(fsm, event) { }
  });

/**
 * Automatic actions to take immediately after calling the transition's
 * ontransition function.  This is documented in the constructor, and is
 * typically provided through the constructor's transitionInfo object, but it
 * is also possible (but highly NOT recommended) to change this dynamically.
 */
qx.OO.addProperty(
  {
    name         : "autoActionsAfterOntransition",
    defaultValue : function(fsm, event) { }
  });


/**
 * The function run when the transition is accepted.  This is documented in
 * the constructor, and is typically provided through the constructor's
 * transitionInfo object, but it is also possible (but highly NOT recommended)
 * to change this dynamically.
 */
qx.OO.addProperty(
  {
    name         : "ontransition",
    defaultValue : function(fsm, event) { }
  });




/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._checkName = function(propValue, propData)
{
  // Ensure that we got a valid state name
  if (typeof(propValue) != "string" || propValue.length < 1)
  {
    throw new Error("Invalid transition name");
  }

  return propValue;
};

qx.Proto._checkPredicate = function(propValue, propData)
{
  // Validate the predicate.  Convert all valid types to function.
  switch(typeof(propValue))
  {
    case "undefined":
      // No predicate means predicate passes
      return function(fsm, event) { return true; };

    case "boolean":
      // Convert boolean predicate to a function which returns that value
      return function(fsm, event) { return propValue; };

    case "function":
      // Use user-provided function.
      return propValue;

    default:
      throw new Error("Invalid transition predicate type: " +
                      typeof(propValue));
      break;
  }
};

qx.Proto._checkNextState = function(propValue, propData)
{
  // Validate nextState.  It must be a string or a number.
  switch(typeof(propValue))
  {
  case "string":
    return propValue;

  case "number":
    // Ensure that it's one of the possible state-change constants
    switch(propValue)
    {
    case qx.util.fsm.FiniteStateMachine.StateChange.CURRENT_STATE:
    case qx.util.fsm.FiniteStateMachine.StateChange.POP_STATE_STACK:
    case qx.util.fsm.FiniteStateMachine.StateChange.TERMINATE:
      return propValue;

    default:
      throw new Error("Invalid transition nextState value: " +
                      propValue +
                      ": nextState must be an explicit state name, " +
                      "or one of the Fsm.StateChange constants");
    }
    break;

  default:
    throw new Error("Invalid transition nextState type: " + typeof(propValue));
    break;
  }
};

qx.Proto._checkOntransition = function(propValue, propData)
{
  // Validate the ontransition function.  Convert undefined to function.
  switch(typeof(propValue) )
  {
  case "undefined":
    // No provided function just means do nothing.  Use a null function.
    return function(fsm, event) { };

  case "function":
    // Use user-provided function.
    return propValue;

  default:
    throw new Error("Invalid ontransition type: " + typeof(propValue));
    break;
  }
};

/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/


/*
---------------------------------------------------------------------------
  EVENT LISTENERS
---------------------------------------------------------------------------
*/



/*
---------------------------------------------------------------------------
  CLASS CONSTANTS
---------------------------------------------------------------------------
*/



/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  return qx.core.Object.prototype.dispose.call(this);
}
