/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_core)

************************************************************************ */

qx.OO.defineClass("qx.event.type.DomEvent", qx.event.type.Event,
function(vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget)
{
  qx.event.type.Event.call(this, vType);

  this.setDomEvent(vDomEvent);
  this.setDomTarget(vDomTarget);

  this.setTarget(vTarget);
  this.setOriginalTarget(vOriginalTarget);
});

qx.OO.addFastProperty({ name : "bubbles", defaultValue : true, noCompute : true });
qx.OO.addFastProperty({ name : "propagationStopped", defaultValue : false, noCompute : true });

qx.OO.addFastProperty({ name : "domEvent", setOnlyOnce : true, noCompute : true });
qx.OO.addFastProperty({ name : "domTarget", setOnlyOnce : true, noCompute : true });

/**
 * The modifiers. A mask of the pressed modifier keys. This is an OR-combination of
 * {@link #SHIFT_MASK}, {@link #CTRL_MASK}, {@link #ALT_MASK} and {@link #META_MASK}.
 */
qx.OO.addCachedProperty({ name : "modifiers", defaultValue : null });


// property computer
qx.Proto._computeModifiers = function() {
    var mask = 0;
    var evt = this.getDomEvent();
    if (evt.shiftKey) mask |= qx.event.type.DomEvent.SHIFT_MASK;
    if (evt.ctrlKey)  mask |= qx.event.type.DomEvent.CTRL_MASK;
    if (evt.altKey)   mask |= qx.event.type.DomEvent.ALT_MASK;
    if (evt.metaKey)  mask |= qx.event.type.DomEvent.META_MASK;
    return mask;
}






/*
---------------------------------------------------------------------------
  SPECIAL KEY SUPPORT
---------------------------------------------------------------------------
*/

/**
 * Returns whether the the ctrl key is pressed.
 *
 * @return {boolean} whether the the ctrl key is pressed.
 */
qx.Proto.isCtrlPressed = function() {
  return this.getDomEvent().ctrlKey;
}

/**
 * Returns whether the the ctrl key is pressed.
 *
 * @return {boolean} whether the the ctrl key is pressed.
 * @deprecated Use {@link #isCtrlPressed} instead.
 */
qx.Proto.getCtrlKey = qx.Proto.isCtrlPressed;


/**
 * Returns whether the the shift key is pressed.
 *
 * @return {boolean} whether the the shift key is pressed.
 */
qx.Proto.isShiftPressed = function() {
  return this.getDomEvent().shiftKey;
}

/**
 * Returns whether the the shift key is pressed.
 *
 * @return {boolean} whether the the shift key is pressed.
 * @deprecated Use {@link #isShiftPressed} instead.
 */
qx.Proto.getShiftKey = qx.Proto.isShiftPressed;


/**
 * Returns whether the the alt key is pressed.
 *
 * @return {boolean} whether the the alt key is pressed.
 */
qx.Proto.isAltPressed = function() {
  return this.getDomEvent().altKey;
}

/**
 * Returns whether the the alt key is pressed.
 *
 * @return {boolean} whether the the alt key is pressed.
 * @deprecated Use {@link #isAltPressed} instead.
 */
qx.Proto.getAltKey = qx.Proto.isAltPressed;


/**
 * Returns whether the the meta key is pressed.
 *
 * @return {boolean} whether the the meta key is pressed.
 */
qx.Proto.isMetaPressed = function() {
  return this.getDomEvent().metaKey;
}


/**
 * Returns whether the ctrl key or (on the Mac) the command key is pressed.
 *
 * @return {boolean} <code>true</code> if the command key is pressed on the Mac
 *         or the ctrl key is pressed on another system.
 */
qx.Proto.isCtrlOrCommandPressed = function() {
  if (qx.sys.Client.getInstance().runsOnMacintosh()) {
    return this.getDomEvent().metaKey;
  } else {
    return this.getDomEvent().ctrlKey;
  }
}







/*
---------------------------------------------------------------------------
  PREVENT DEFAULT
---------------------------------------------------------------------------
*/

if(qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto.setDefaultPrevented = function(vValue)
  {
    if (!vValue) {
      return this.error("It is not possible to set preventDefault to false if it was true before!", "setDefaultPrevented");
    }

    this.getDomEvent().returnValue = false;

    qx.event.type.Event.prototype.setDefaultPrevented.call(this, vValue);
  }
}
else
{
  qx.Proto.setDefaultPrevented = function(vValue)
  {
    if (!vValue) {
      return this.error("It is not possible to set preventDefault to false if it was true before!", "setDefaultPrevented");
    }

    this.getDomEvent().preventDefault();
    this.getDomEvent().returnValue = false;

    qx.event.type.Event.prototype.setDefaultPrevented.call(this, vValue);
  }
}







/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  this._valueDomEvent = null;
  this._valueDomTarget = null;

  return qx.event.type.Event.prototype.dispose.call(this);
}




/** {int} The modifier mask for the shift key. */
qx.Class.SHIFT_MASK = 1;

/** {int} The modifier mask for the control key. */
qx.Class.CTRL_MASK = 2;

/** {int} The modifier mask for the alt key. */
qx.Class.ALT_MASK = 4;

/** {int} The modifier mask for the meta key (e.g. apple key on Macs). */
qx.Class.META_MASK = 8;
