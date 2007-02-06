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
 * A selection model.
 *
 * @event changeSelection {qx.event.type.Event} Fired when the selection has
 *        changed.
 */
qx.OO.defineClass("qx.ui.table.SelectionModel", qx.core.Target,
function() {
  qx.core.Target.call(this);

  this._selectedRangeArr = [];
  this._anchorSelectionIndex = -1;
  this._leadSelectionIndex = -1;
  this.hasBatchModeRefCount = 0;
  this._hadChangeEventInBatchMode = false;
});


/** {int} The selection mode "none". Nothing can ever be selected. */
qx.Class.NO_SELECTION = 1;

/** {int} The selection mode "single". This mode only allows one selected item. */
qx.Class.SINGLE_SELECTION = 2;

/**
 * (int) The selection mode "single interval". This mode only allows one
 * continuous interval of selected items.
 */
qx.Class.SINGLE_INTERVAL_SELECTION = 3;

/**
 * (int) The selection mode "multiple interval". This mode only allows any
 * selection.
 */
qx.Class.MULTIPLE_INTERVAL_SELECTION = 4;


/**
 * (int) the selection mode.
 */
qx.OO.addProperty({ name:"selectionMode", type:"number",
  defaultValue:qx.Class.SINGLE_SELECTION,
  allowNull:false,
  possibleValues:[ qx.Class.NO_SELECTION,
           qx.Class.SINGLE_SELECTION,
           qx.Class.SINGLE_INTERVAL_SELECTION,
           qx.Class.MULTIPLE_INTERVAL_SELECTION  ] });

// selectionMode property modifier
qx.Proto._modifySelectionMode = function(selectionMode) {
  if (selectionMode == qx.ui.table.SelectionModel.NO_SELECTION) {
    this.clearSelection();
  }
  return true;
}


/**
 * <p>Activates / Deactivates batch mode. In batch mode, no change events will be thrown but
 * will be collected instead. When batch mode is turned off again and any events have
 * been collected, one event is thrown to inform the listeners.</p>
 *
 * <p>This method supports nested calling, i. e. batch mode can be turned more than once.
 * In this case, batch mode will not end until it has been turned off once for each
 * turning on.</p>
 *
 * @param batchMode {Boolean} true to activate batch mode, false to deactivate
 * @return {Boolean} true if batch mode is active, false otherwise
 * @throws Error if batch mode is turned off once more than it has been turned on
 */
qx.Proto.setBatchMode = function(batchMode) {
  if (batchMode){
    this.hasBatchModeRefCount += 1;
  } else {
    if (this.hasBatchModeRefCount == 0){
      throw new Error("Try to turn off batch mode althoug it was not turned on.")
    }
    this.hasBatchModeRefCount -= 1;
    if (this._hadChangeEventInBatchMode){
      this._hadChangeEventInBatchMode = false;
      this._fireChangeSelection();
    }
  }
  return this.hasBatchMode();
}


/**
 * <p>Returns whether batch mode is active. See setter for a description of batch mode.</p>
 *
 * @return {Boolean} true if batch mode is active, false otherwise
 */
qx.Proto.hasBatchMode = function() {
  return this.hasBatchModeRefCount > 0;
}


/**
 * Returns the first argument of the last call to {@link #setSelectionInterval()},
 * {@link #addSelectionInterval()} or {@link #removeSelectionInterval()}.
 *
 * @return {Integer} the ancor selection index.
 */
qx.Proto.getAnchorSelectionIndex = function() {
  return this._anchorSelectionIndex;
}


/**
 * Returns the second argument of the last call to {@link #setSelectionInterval()},
 * {@link #addSelectionInterval()} or {@link #removeSelectionInterval()}.
 *
 * @return {Integer} the lead selection index.
 */
qx.Proto.getLeadSelectionIndex = function() {
  return this._leadSelectionIndex;
}


/**
 * Clears the selection.
 */
qx.Proto.clearSelection = function() {
  if (! this.isSelectionEmpty()) {
    this._clearSelection();
    this._fireChangeSelection();
  }
}


/**
 * Returns whether the selection is empty.
 *
 * @return {Boolean} whether the selection is empty.
 */
qx.Proto.isSelectionEmpty = function() {
  return this._selectedRangeArr.length == 0;
}


/**
 * Returns the number of selected items.
 *
 * @return {Integer} the number of selected items.
 */
qx.Proto.getSelectedCount = function() {
  var selectedCount = 0;
  for (var i = 0; i < this._selectedRangeArr.length; i++) {
    var range = this._selectedRangeArr[i];
    selectedCount += range.maxIndex - range.minIndex + 1;
  }

  return selectedCount;
}


/**
 * Returns whether a index is selected.
 *
 * @param index {Integer} the index to check.
 * @return {Boolean} whether the index is selected.
 */
qx.Proto.isSelectedIndex = function(index) {
  for (var i = 0; i < this._selectedRangeArr.length; i++) {
    var range = this._selectedRangeArr[i];

    if (index >= range.minIndex && index <= range.maxIndex) {
      return true;
    }
  }

  return false;
}


/**
 * Returns the selected ranges as an array. Each array element has a
 * <code>minIndex</code> and a <code>maxIndex</code> property.
 *
 * @return {Map[]} the selected ranges.
 */
qx.Proto.getSelectedRanges = function() {
  // clone the selection array and the individual elements - this prevents the
  // caller from messing with the internal model
  var retVal = [];
  for (var i = 0; i < this._selectedRangeArr.length; i++) {
    retVal.push({minIndex: this._selectedRangeArr[i].minIndex,
                 maxIndex: this._selectedRangeArr[i].maxIndex});
  }
  return retVal;
}


/**
 * Calls a iterator function for each selected index.
 * <p>
 * Usage Example:
 * <pre>
 * var selectedRowData = [];
 * mySelectionModel.iterateSelection(function(index) {
 *   selectedRowData.push(myTableModel.getRowData(index));
 * });
 * </pre>
 *
 * @param iterator {Function} the function to call for each selected index.
 *        Gets the current index as parameter.
 * @param object {var ? null} the object to use when calling the handler.
 *        (this object will be available via "this" in the iterator)
 */
qx.Proto.iterateSelection = function(iterator, object) {
  for (var i = 0; i < this._selectedRangeArr.length; i++) {
    for (var j = this._selectedRangeArr[i].minIndex; j <= this._selectedRangeArr[i].maxIndex; j++) {
      iterator.call(object, j);
    }
  }
};


/**
 * Sets the selected interval. This will clear the former selection.
 *
 * @param fromIndex {Integer} the first index of the selection (including).
 * @param toIndex {Integer} the last index of the selection (including).
 */
qx.Proto.setSelectionInterval = function(fromIndex, toIndex) {
  var SelectionModel = qx.ui.table.SelectionModel;

  switch(this.getSelectionMode()) {
    case SelectionModel.NO_SELECTION:
      return;
    case SelectionModel.SINGLE_SELECTION:
      fromIndex = toIndex;
      break;
  }

  this._clearSelection();
  this._addSelectionInterval(fromIndex, toIndex);

  this._fireChangeSelection();
}


/**
 * Adds a selection interval to the current selection.
 *
 * @param fromIndex {Integer} the first index of the selection (including).
 * @param toIndex {Integer} the last index of the selection (including).
 */
qx.Proto.addSelectionInterval = function(fromIndex, toIndex) {
  var SelectionModel = qx.ui.table.SelectionModel;
  switch (this.getSelectionMode()) {
    case SelectionModel.NO_SELECTION:
      return;
    case SelectionModel.MULTIPLE_INTERVAL_SELECTION:
      this._addSelectionInterval(fromIndex, toIndex);
      this._fireChangeSelection();
      break;
    default:
      this.setSelectionInterval(fromIndex, toIndex);
      break;
  }
}


/**
 * Removes a interval from the current selection.
 *
 * @param fromIndex {Integer} the first index of the interval (including).
 * @param toIndex {Integer} the last index of the interval (including).
 */
qx.Proto.removeSelectionInterval = function(fromIndex, toIndex) {
  this._anchorSelectionIndex = fromIndex;
  this._leadSelectionIndex = toIndex;

  var minIndex = Math.min(fromIndex, toIndex);
  var maxIndex = Math.max(fromIndex, toIndex);

  // Crop the affected ranges
  for (var i = 0; i < this._selectedRangeArr.length; i++) {
    var range = this._selectedRangeArr[i];

    if (range.minIndex > maxIndex) {
      // We are done
      break;
    } else if (range.maxIndex >= minIndex) {
      // This range is affected
      var minIsIn = (range.minIndex >= minIndex) && (range.minIndex <= maxIndex);
      var maxIsIn = (range.maxIndex >= minIndex) && (range.maxIndex <= maxIndex);

      if (minIsIn && maxIsIn) {
        // This range is removed completely
        this._selectedRangeArr.splice(i, 1);

        // Check this index another time
        i--;
      } else if (minIsIn) {
        // The range is cropped from the left
        range.minIndex = maxIndex + 1;
      } else if (maxIsIn) {
        // The range is cropped from the right
        range.maxIndex = minIndex - 1;
      } else {
        // The range is split
        var newRange = { minIndex:maxIndex + 1, maxIndex:range.maxIndex }
        this._selectedRangeArr.splice(i + 1, 0, newRange);

        range.maxIndex = minIndex - 1;

        // We are done
        break;
      }
    }
  }

  //this._dumpRanges();

  this._fireChangeSelection();
}


/**
 * Clears the selection, but doesn't inform the listeners.
 */
qx.Proto._clearSelection = function() {
  this._selectedRangeArr = [];
  this._anchorSelectionIndex = -1;
  this._leadSelectionIndex = -1;
}


/**
 * Adds a selection interval to the current selection, but doesn't inform
 * the listeners.
 *
 * @param fromIndex {Integer} the first index of the selection (including).
 * @param toIndex {Integer} the last index of the selection (including).
 */
qx.Proto._addSelectionInterval = function(fromIndex, toIndex) {
  this._anchorSelectionIndex = fromIndex;
  this._leadSelectionIndex = toIndex;

  var minIndex = Math.min(fromIndex, toIndex);
  var maxIndex = Math.max(fromIndex, toIndex);

  // Find the index where the new range should be inserted
  var newRangeIndex = 0;
  for (; newRangeIndex < this._selectedRangeArr.length; newRangeIndex++) {
    var range = this._selectedRangeArr[newRangeIndex];
    if (range.minIndex > minIndex) {
      break;
    }
  }

  // Add the new range
  this._selectedRangeArr.splice(newRangeIndex, 0, { minIndex:minIndex, maxIndex:maxIndex });

  // Merge overlapping ranges
  var lastRange = this._selectedRangeArr[0];
  for (var i = 1; i < this._selectedRangeArr.length; i++) {
    var range = this._selectedRangeArr[i];

    if (lastRange.maxIndex + 1 >= range.minIndex) {
      // The ranges are overlapping -> merge them
      lastRange.maxIndex = Math.max(lastRange.maxIndex, range.maxIndex);

      // Remove the current range
      this._selectedRangeArr.splice(i, 1);

      // Check this index another time
      i--;
    } else {
      lastRange = range;
    }
  }

  //this._dumpRanges();
}


/**
 * Logs the current ranges for debug perposes.
 */
qx.Proto._dumpRanges = function() {
  var text = "Ranges:";
  for (var i = 0; i < this._selectedRangeArr.length; i++) {
    var range = this._selectedRangeArr[i];
    text += " [" + range.minIndex + ".." + range.maxIndex + "]";
  }
  this.debug(text);
}


/**
 * Fires the "changeSelection" event to all registered listeners. If the selection model
 * currently is in batch mode, only one event will be thrown when batch mode is ended.
 */
qx.Proto._fireChangeSelection = function() {
  //In batch mode, remember event but do not throw (yet)
  if (this.hasBatchMode()){
    this._hadChangeEventInBatchMode = true;

  //If not in batch mode, throw event
  } else if (this.hasEventListeners("changeSelection")) {
    this.dispatchEvent(new qx.event.type.Event("changeSelection"), true);
  }
}
