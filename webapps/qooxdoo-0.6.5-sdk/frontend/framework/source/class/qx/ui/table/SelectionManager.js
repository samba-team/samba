/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************

#module(ui_table)

************************************************************************ */

/**
 * A selection manager. This is a helper class that handles all selection
 * related events and updates a SelectionModel.
 * <p>
 * Widgets that support selection should use this manager. This way the only
 * thing the widget has to do is mapping mouse or key events to indexes and
 * call the corresponding handler method.
 *
 * @see SelectionModel
 */
qx.OO.defineClass("qx.ui.table.SelectionManager", qx.core.Object,
function() {
  qx.core.Object.call(this);
});


/**
 * The selection model where to set the selection changes.
 */
qx.OO.addProperty({ name:"selectionModel", type:"object", instance:"qx.ui.table.SelectionModel" });


/**
 * Handles the mouse down event.
 *
 * @param index {Integer} the index the mouse is pointing at.
 * @param evt {Map} the mouse event.
 */
qx.Proto.handleMouseDown = function(index, evt) {
  if (evt.isLeftButtonPressed()) {
    var selectionModel = this.getSelectionModel();
    if (!selectionModel.isSelectedIndex(index)) {
      // This index is not selected -> We react when the mouse is pressed (because of drag and drop)
      this._handleSelectEvent(index, evt);
      this._lastMouseDownHandled = true;
    } else {
      // This index is already selected -> We react when the mouse is released (because of drag and drop)
      this._lastMouseDownHandled = false;
    }
  } else if (evt.isRightButtonPressed() && evt.getModifiers() == 0) {
    var selectionModel = this.getSelectionModel();
    if (!selectionModel.isSelectedIndex(index)) {
      // This index is not selected -> Set the selection to this index
      selectionModel.setSelectionInterval(index, index);
    }
  }
}


/**
 * Handles the mouse up event.
 *
 * @param index {Integer} the index the mouse is pointing at.
 * @param evt {Map} the mouse event.
 */
qx.Proto.handleMouseUp = function(index, evt) {
  if (evt.isLeftButtonPressed() && !this._lastMouseDownHandled) {
    this._handleSelectEvent(index, evt);
  }
}


/**
 * Handles the mouse click event.
 *
 * @param index {Integer} the index the mouse is pointing at.
 * @param evt {Map} the mouse event.
 */
qx.Proto.handleClick = function(index, evt) {
}


/**
 * Handles the key down event that is used as replacement for mouse clicks
 * (Normally space).
 *
 * @param index {Integer} the index that is currently focused.
 * @param evt {Map} the key event.
 */
qx.Proto.handleSelectKeyDown = function(index, evt) {
  this._handleSelectEvent(index, evt);
};


/**
 * Handles a key down event that moved the focus (E.g. up, down, home, end, ...).
 *
 * @param index {Integer} the index that is currently focused.
 * @param evt {Map} the key event.
 */
qx.Proto.handleMoveKeyDown = function(index, evt) {
  var selectionModel = this.getSelectionModel();
  switch (evt.getModifiers()) {
    case 0:
      selectionModel.setSelectionInterval(index, index);
      break;
    case qx.event.type.DomEvent.SHIFT_MASK:
      var anchor = selectionModel.getAnchorSelectionIndex();
      if (anchor == -1) {
        selectionModel.setSelectionInterval(index, index);
      } else {
        selectionModel.setSelectionInterval(anchor, index);
      }
      break;
  }
}


/**
 * Handles a select event.
 *
 * @param index {Integer} the index the event is pointing at.
 * @param evt {Map} the mouse event.
 */
qx.Proto._handleSelectEvent = function(index, evt) {
  var selectionModel = this.getSelectionModel();
  if (evt.isShiftPressed()) {
    var leadIndex = selectionModel.getLeadSelectionIndex();
    if (index != leadIndex || selectionModel.isSelectionEmpty()) {
      // The lead selection index was changed
      var anchorIndex = selectionModel.getAnchorSelectionIndex();
      if (anchorIndex == -1) {
          anchorIndex = index;
      }
      if (evt.isCtrlOrCommandPressed()) {
        selectionModel.addSelectionInterval(anchorIndex, index);
      } else {
        selectionModel.setSelectionInterval(anchorIndex, index);
      }
    }
  } else if (evt.isCtrlOrCommandPressed()) {
    if (selectionModel.isSelectedIndex(index)) {
      selectionModel.removeSelectionInterval(index, index);
    } else {
      selectionModel.addSelectionInterval(index, index);
    }
  } else {
    selectionModel.setSelectionInterval(index, index);
  }
}
