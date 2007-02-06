/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_dragdrop)

************************************************************************ */

/*!
  The event object for drag and drop sessions
*/
qx.OO.defineClass("qx.event.type.DragEvent", qx.event.type.MouseEvent,
function(vType, vMouseEvent, vTarget, vRelatedTarget)
{
  this._mouseEvent = vMouseEvent;

  var vOriginalTarget = null;

  switch(vType)
  {
    case "dragstart":
    case "dragover":
      vOriginalTarget = vMouseEvent.getOriginalTarget();
  }

  qx.event.type.MouseEvent.call(this, vType, vMouseEvent.getDomEvent(), vTarget.getElement(), vTarget, vOriginalTarget, vRelatedTarget);
});





/*
---------------------------------------------------------------------------
  UTILITIY
---------------------------------------------------------------------------
*/

qx.Proto.getMouseEvent = function() {
  return this._mouseEvent;
}






/*
---------------------------------------------------------------------------
  APPLICATION CONNECTION
---------------------------------------------------------------------------
*/

qx.Proto.startDrag = function()
{
  if (this.getType() != "dragstart") {
    throw new Error("qx.event.type.DragEvent startDrag can only be called during the dragstart event: " + this.getType());
  }

  this.stopPropagation();
  qx.event.handler.DragAndDropHandler.getInstance().startDrag();
}






/*
---------------------------------------------------------------------------
  DATA SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.addData = function(sType, oData) {
  qx.event.handler.DragAndDropHandler.getInstance().addData(sType, oData);
}

qx.Proto.getData = function(sType) {
  return qx.event.handler.DragAndDropHandler.getInstance().getData(sType);
}

qx.Proto.clearData = function() {
  qx.event.handler.DragAndDropHandler.getInstance().clearData();
}

qx.Proto.getDropDataTypes = function() {
  return qx.event.handler.DragAndDropHandler.getInstance().getDropDataTypes();
}






/*
---------------------------------------------------------------------------
  ACTION SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.addAction = function(sAction) {
  qx.event.handler.DragAndDropHandler.getInstance().addAction(sAction);
}

qx.Proto.removeAction = function(sAction) {
  qx.event.handler.DragAndDropHandler.getInstance().removeAction(sAction);
}

qx.Proto.getAction = function() {
  return qx.event.handler.DragAndDropHandler.getInstance().getCurrentAction();
}

qx.Proto.clearActions = function() {
  qx.event.handler.DragAndDropHandler.getInstance().clearActions();
}






/*
---------------------------------------------------------------------------
  USER FEEDBACK SUPPORT
---------------------------------------------------------------------------
*/

/**
 * Sets the widget to show as feedback for the user. This widget should
 * represent the object(s) the user is dragging.
 *
 * @param widget {qx.ui.core.Widget} the feedback widget.
 * @param deltaX {int ? 10} the number of pixels the top-left corner of the widget
 *        should be away from the mouse cursor in x direction.
 * @param deltaY {int ? 10} the number of pixels the top-left corner of the widget
 *        should be away from the mouse cursor in y direction.
 * @param autoDisposeWidget {boolean} whether the widget should be disposed when
 *        dragging is finished or cancelled.
 */
qx.Proto.setFeedbackWidget = function(widget, deltaX, deltaY, autoDisposeWidget) {
  qx.event.handler.DragAndDropHandler.getInstance().setFeedbackWidget(widget, deltaX, deltaY, autoDisposeWidget);
};






/*
---------------------------------------------------------------------------
  CURSPOR POSITIONING SUPPORT
---------------------------------------------------------------------------
*/

/**
 * Sets the position of the cursor feedback (the icon showing whether dropping
 * is allowed at the current position and which action a drop will do).
 *
 * @param deltaX {int} The number of pixels the top-left corner of the
 *        cursor feedback should be away from the mouse cursor in x direction.
 * @param deltaY {int} The number of pixels the top-left corner of the
 *        cursor feedback should be away from the mouse cursor in y direction.
 */
qx.Proto.setCursorPosition = function(deltaX, deltaY) {
  qx.event.handler.DragAndDropHandler.getInstance().setCursorPosition(deltaX, deltaY);
};






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

  this._mouseEvent = null;

  return qx.event.type.MouseEvent.prototype.dispose.call(this);
}
