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

#module(ui_form)

************************************************************************ */

/**
 * This class represents a selection and manage incoming events for widgets
 * which need selection support.
 *
 * @event changeSelection {qx.event.type.DataEvent} sets the data property of the event object to an arryas of selected items.
 */
qx.OO.defineClass("qx.manager.selection.SelectionManager", qx.core.Target,
function(vBoundedWidget)
{
  qx.core.Target.call(this);

  this._selectedItems = new qx.type.Selection(this);

  if (qx.util.Validation.isValid(vBoundedWidget)) {
    this.setBoundedWidget(vBoundedWidget);
  }
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
This contains the currently assigned widget (qx.ui.form.List, ...)
*/
qx.OO.addProperty({ name : "boundedWidget", type : "object" });

/*!
Should multiple selection be allowed?
*/
qx.OO.addProperty({ name : "multiSelection", type : "boolean", defaultValue : true });

/*!
Enable drag selection?
*/
qx.OO.addProperty({ name : "dragSelection", type : "boolean", defaultValue : true });

/*!
Should the user be able to select
*/
qx.OO.addProperty({ name : "canDeselect", type : "boolean", defaultValue : true });

/*!
Should a change event be fired?
*/
qx.OO.addProperty({ name : "fireChange", type : "boolean", defaultValue : true });

/*!
The current anchor in range selections.
*/
qx.OO.addProperty({ name : "anchorItem", type : "object" });

/*!
The last selected item
*/
qx.OO.addProperty({ name : "leadItem", type : "object" });

/*!
Grid selection
*/
qx.OO.addProperty({ name : "multiColumnSupport", type : "boolean", defaultValue : false });






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyAnchorItem = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    this.renderItemAnchorState(propOldValue, false);
  }

  if (propValue) {
    this.renderItemAnchorState(propValue, true);
  }

  return true;
}

qx.Proto._modifyLeadItem = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    this.renderItemLeadState(propOldValue, false);
  }

  if (propValue) {
    this.renderItemLeadState(propValue, true);
  }

  return true;
}






/*
---------------------------------------------------------------------------
  MAPPING TO BOUNDED WIDGET
---------------------------------------------------------------------------
*/

qx.Proto._getFirst = function() {
  return this.getBoundedWidget().getFirstVisibleChild();
}

qx.Proto._getLast = function() {
  return this.getBoundedWidget().getLastVisibleChild();
}

qx.Proto.getFirst = function()
{
  var vItem = this._getFirst();
  if (vItem) {
    return vItem.isEnabled() ? vItem : this.getNext(vItem);
  }
}

qx.Proto.getLast = function()
{
  var vItem = this._getLast();
  if (vItem) {
    return vItem.isEnabled() ? vItem : this.getPrevious(vItem);
  }
}

qx.Proto.getItems = function() {
  return this.getBoundedWidget().getChildren();
}

qx.Proto.getNextSibling = function(vItem) {
  return vItem.getNextSibling();
}

qx.Proto.getPreviousSibling = function(vItem) {
  return vItem.getPreviousSibling();
}

qx.Proto.getNext = function(vItem)
{
  while(vItem)
  {
    vItem = this.getNextSibling(vItem);

    if (!vItem) {
      break;
    }

    if (this.getItemEnabled(vItem)) {
      return vItem;
    }
  }

  return null;
}

qx.Proto.getPrevious = function(vItem)
{
  while(vItem)
  {
    vItem = this.getPreviousSibling(vItem);

    if (!vItem) {
      break;
    }

    if (this.getItemEnabled(vItem)) {
      return vItem;
    }
  }

  return null;
}

qx.Proto.isBefore = function(vItem1, vItem2)
{
  var cs = this.getItems();
  return cs.indexOf(vItem1) < cs.indexOf(vItem2);
}

qx.Proto.isEqual = function(vItem1, vItem2) {
  return vItem1 == vItem2;
}



/*
---------------------------------------------------------------------------
  MAPPING TO ITEM PROPERTIES
---------------------------------------------------------------------------
*/

qx.Proto.getItemHashCode = function(vItem) {
  return vItem.toHashCode();
}





/*
---------------------------------------------------------------------------
  MAPPING TO ITEM DIMENSIONS
---------------------------------------------------------------------------
*/

qx.Proto.scrollItemIntoView = function(vItem, vTopLeft) {
  vItem.scrollIntoView(vTopLeft);
}

qx.Proto.getItemLeft = function(vItem) {
  return vItem.getOffsetLeft();
}

qx.Proto.getItemTop = function(vItem) {
  return vItem.getOffsetTop();
}

qx.Proto.getItemWidth = function(vItem) {
  return vItem.getOffsetWidth();
}

qx.Proto.getItemHeight = function(vItem) {
  return vItem.getOffsetHeight();
}

qx.Proto.getItemEnabled = function(vItem) {
  return vItem.getEnabled();
}






/*
---------------------------------------------------------------------------
  ITEM STATE MANAGMENT
---------------------------------------------------------------------------
*/

qx.Proto.renderItemSelectionState = function(vItem, vIsSelected)
{
  vIsSelected ? vItem.addState("selected") : vItem.removeState("selected");

  if (vItem.handleStateChange) {
    vItem.handleStateChange();
  }
}

qx.Proto.renderItemAnchorState = function(vItem, vIsAnchor)
{
  vIsAnchor ? vItem.addState("anchor") : vItem.removeState("anchor");

  if (vItem.handleStateChange != null) {
    vItem.handleStateChange();
  }
}

qx.Proto.renderItemLeadState = function(vItem, vIsLead)
{
  vIsLead ? vItem.addState("lead") : vItem.removeState("lead");

  if (vItem.handleStateChange != null) {
    vItem.handleStateChange();
  }
}





/*
---------------------------------------------------------------------------
  SELECTION HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.getItemSelected = function(vItem) {
  return this._selectedItems.contains(vItem);
}

/*!
Make a single item selected / not selected

#param vItem[qx.ui.core.Widget]: Item which should be selected / not selected
#param vSelected[Boolean]: Should this item be selected?
*/
qx.Proto.setItemSelected = function(vItem, vSelected)
{
  var hc = this.getItemHashCode(vItem);

  switch(this.getMultiSelection())
  {
    // Multiple item selection is allowed
    case true:
      if (!this.getItemEnabled(vItem)) {
        return;
      }

      // If selection state is not to be changed => return
      if (this.getItemSelected(vItem) == vSelected) {
        return;
      }

      // Otherwise render new state
      this.renderItemSelectionState(vItem, vSelected);

      // Add item to selection hash / delete it from there
      vSelected ? this._selectedItems.add(vItem) : this._selectedItems.remove(vItem);

      // Dispatch change Event
      this._dispatchChange();

      break;



    // Multiple item selection is NOT allowed
    case false:
      var item0 = this.getSelectedItems()[0];



      if (vSelected)
      {
        // Precheck for any changes
        var old = item0;

        if (this.isEqual(vItem, old)) {
          return;
        }

        // Reset rendering of previous selected item
        if (old != null) {
          this.renderItemSelectionState(old, false);
        }

        // Render new item as selected
        this.renderItemSelectionState(vItem, true);

        // Reset current selection hash
        this._selectedItems.removeAll();

        // Add new one
        this._selectedItems.add(vItem);

        // Dispatch change Event
        this._dispatchChange();
      }
      else
      {
        // Pre-check if item is currently selected
        // Do not allow deselection in single selection mode
        if (!this.isEqual(item0, vItem))
        {
          // Reset rendering as selected item
          this.renderItemSelectionState(vItem, false);

          // Reset current selection hash
          this._selectedItems.removeAll();

          // Dispatch change Event
          this._dispatchChange();
        }
      }

      break;

  }
}








/*!
  Get the selected items (objects)
*/
qx.Proto.getSelectedItems = function() {
  return this._selectedItems.toArray();
}

qx.Proto.getSelectedItem = function() {
  return this._selectedItems.getFirst();
}

/*!
Select given items

#param vItems[Array of Widgets]: Items to select
*/
qx.Proto.setSelectedItems = function(vItems)
{
  var oldVal = this._getChangeValue();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Deselect all currently selected items
  this._deselectAll();

  // Apply new selection
  var vItem;
  var vItemLength = vItems.length;

  for (var i=0; i<vItemLength; i++)
  {
    vItem = vItems[i];

    if (!this.getItemEnabled(vItem)) {
      continue;
    }

    // Add item to selection
    this._selectedItems.add(vItem);

    // Render new state for item
    this.renderItemSelectionState(vItem, true);
  }

  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if (oldFireChange && this._hasChanged(oldVal)) {
    this._dispatchChange();
  }
}


qx.Proto.setSelectedItem = function(vItem)
{
  if (!vItem) {
    return;
  }

  if (!this.getItemEnabled(vItem)) {
    return;
  }

  var oldVal = this._getChangeValue();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Deselect all currently selected items
  this._deselectAll();

  // Add item to selection
  this._selectedItems.add(vItem);

  // Render new state for item
  this.renderItemSelectionState(vItem, true);

  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if (oldFireChange && this._hasChanged(oldVal)) {
    this._dispatchChange();
  }
}





/*!
  Select all items.
*/
qx.Proto.selectAll = function()
{
  var oldVal = this._getChangeValue();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Call sub method to select all items
  this._selectAll();

  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if (oldFireChange && this._hasChanged(oldVal)) {
    this._dispatchChange();
  }
}

/*!
  Sub method for selectAll. Handles the real work
  to select all items.
*/
qx.Proto._selectAll = function()
{
  if (!this.getMultiSelection()) {
    return;
  }

  var vItem;
  var vItems = this.getItems();
  var vItemsLength = vItems.length;

  // Reset current selection hash
  this._selectedItems.removeAll();

  for (var i=0; i<vItemsLength; i++)
  {
    vItem = vItems[i];

    if (!this.getItemEnabled(vItem)) {
      continue;
    }

    // Add item to selection
    this._selectedItems.add(vItem);

    // Render new state for item
    this.renderItemSelectionState(vItem, true);
  }

  return true;
}





/*!
  Deselect all items.
*/
qx.Proto.deselectAll = function()
{
  var oldVal = this._getChangeValue();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Call sub method to deselect all items
  this._deselectAll();

  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if (oldFireChange && this._hasChanged(oldVal))
    this._dispatchChange();
  }

/*!
  Sub method for deselectAll. Handles the real work
  to deselect all items.
*/
qx.Proto._deselectAll = function()
{
  // Render new state for items
  var items = this._selectedItems.toArray();
  for (var i = 0; i < items.length; i++) {
    this.renderItemSelectionState(items[i], false);
  }

  // Delete all entries in selectedItems hash
  this._selectedItems.removeAll();

  return true;
}




/*!
Select a range of items.

#param vItem1[qx.ui.core.Widget]: Start item
#param vItem2[qx.ui.core.Widget]: Stop item
*/
qx.Proto.selectItemRange = function(vItem1, vItem2)
{
  var oldVal = this._getChangeValue();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Call sub method to select the range of items
  this._selectItemRange(vItem1, vItem2, true);

  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if (oldFireChange && this._hasChanged(oldVal)) {
    this._dispatchChange();
  }
}




/*!
Sub method for selectItemRange. Handles the real work
to select a range of items.

#param vItem1[qx.ui.core.Widget]: Start item
#param vItem2[qx.ui.core.Widget]: Stop item
#param vDelect[Boolean]: Deselect currently selected items first?
*/
qx.Proto._selectItemRange = function(vItem1, vItem2, vDeselect)
{
  // this.debug("SELECT_RANGE: " + vItem1.toText() + "<->" + vItem2.toText());
  // this.debug("SELECT_RANGE: " + vItem1.pos + "<->" + vItem2.pos);

  // Pre-Check a revert call if vItem2 is before vItem1
  if (this.isBefore(vItem2, vItem1)) {
    return this._selectItemRange(vItem2, vItem1, vDeselect);
  }

  // Deselect all
  if (vDeselect) {
    this._deselectAll();
  }

  var vCurrentItem = vItem1;

  while (vCurrentItem != null)
  {
    if (this.getItemEnabled(vCurrentItem))
    {
      // Add item to selection
      this._selectedItems.add(vCurrentItem);

      // Render new state for item
      this.renderItemSelectionState(vCurrentItem, true);
    }

    // Stop here if we reached target item
    if (this.isEqual(vCurrentItem, vItem2)) {
      break;
    }

    // Get next item
    vCurrentItem = this.getNext(vCurrentItem);
  }

  return true;
}

/*!
Internal method for deselection of ranges.

#param vItem1[qx.ui.core.Widget]: Start item
#param vItem2[qx.ui.core.Widget]: Stop item
*/
qx.Proto._deselectItemRange = function(vItem1, vItem2)
{
  // Pre-Check a revert call if vItem2 is before vItem1
  if (this.isBefore(vItem2, vItem1)) {
    return this._deselectItemRange(vItem2, vItem1);
  }

  var vCurrentItem = vItem1;

  while (vCurrentItem != null)
  {
    // Add item to selection
    this._selectedItems.remove(vCurrentItem);

    // Render new state for item
    this.renderItemSelectionState(vCurrentItem, false);

    // Stop here if we reached target item
    if (this.isEqual(vCurrentItem, vItem2)) {
      break;
    }

    // Get next item
    vCurrentItem = this.getNext(vCurrentItem);
  }
}


/*
---------------------------------------------------------------------------
  MOUSE EVENT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._activeDragSession = false;

qx.Proto.handleMouseDown = function(vItem, e)
{
  // Only allow left and right button
  if (!e.isLeftButtonPressed() && !e.isRightButtonPressed()) {
    return;
  }

  // Keep selection on right click on already selected item
  if (e.isRightButtonPressed() && this.getItemSelected(vItem)) {
    return;
  }

  // Shift Key
  //   or
  // Click on an unseleted item (without Strg)
  if (e.getShiftKey() || this.getDragSelection() || (!this.getItemSelected(vItem) && !e.getCtrlKey()))
  {
    // Handle event
    this._onmouseevent(vItem, e);
  }
  else
  {
    // Update lead item
    this.setLeadItem(vItem);
  }


  // Handle dragging
  this._activeDragSession = this.getDragSelection();

  if (this._activeDragSession)
  {
    // Add mouseup listener and register as capture widget
    this.getBoundedWidget().addEventListener("mouseup", this._ondragup, this);
    this.getBoundedWidget().setCapture(true);
  }
}

qx.Proto._ondragup = function(e)
{
  this.getBoundedWidget().removeEventListener("mouseup", this._ondragup, this);
  this.getBoundedWidget().setCapture(false);
  this._activeDragSession = false;
}

qx.Proto.handleMouseUp = function(vItem, e)
{
  if (!e.isLeftButtonPressed()) {
    return;
  }

  if (e.getCtrlKey() || this.getItemSelected(vItem) && !this._activeDragSession) {
    this._onmouseevent(vItem, e);
  }

  if (this._activeDragSession)
  {
    this._activeDragSession = false;
    this.getBoundedWidget().setCapture(false);
  }
}

qx.Proto.handleMouseOver = function(oItem, e)
{
  if (! this.getDragSelection() || !this._activeDragSession) {
    return;
  }

  this._onmouseevent(oItem, e, true);
}

// currently unused placeholder
qx.Proto.handleClick = function(vItem, e) {}

// currently unused placeholder
qx.Proto.handleDblClick = function(vItem, e) {}


/*!
Internal handler for all mouse events bound to this manager.
*/
qx.Proto._onmouseevent = function(oItem, e, bOver)
{
  if (!this.getItemEnabled(oItem)) {
    return;
  }

  // ********************************************************************
  //   Init
  // ********************************************************************

  // Cache current (old) values
  var oldVal = this._getChangeValue();
  var oldLead = this.getLeadItem();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Cache selection and count
  var selectedItems = this.getSelectedItems();
  var selectedCount = selectedItems.length;

  // Update lead item
  this.setLeadItem(oItem);

  // Cache current anchor item
  var currentAnchorItem = this.getAnchorItem();

  // Cache keys pressed
  var vCtrlKey = e.getCtrlKey();
  var vShiftKey = e.getShiftKey();


  // ********************************************************************
  //   Do we need to update the anchor?
  // ********************************************************************

  if (!currentAnchorItem || selectedCount == 0 || (vCtrlKey && !vShiftKey && this.getMultiSelection() && !this.getDragSelection()))
  {
    this.setAnchorItem(oItem);
    currentAnchorItem = oItem;
  }



  // ********************************************************************
  //   Mode #1: Replace current selection with new one
  // ********************************************************************
  if ((!vCtrlKey && !vShiftKey && !this._activeDragSession || !this.getMultiSelection()))
  {
    if (!this.getItemEnabled(oItem)) {
      return;
    }

    // Remove current selection
    this._deselectAll();

    // Update anchor item
    this.setAnchorItem(oItem);

    if (this._activeDragSession)
    {
      // a little bit hacky, but seems to be a fast way to detect if we slide to top or to bottom
      this.scrollItemIntoView((this.getBoundedWidget().getScrollTop() > (this.getItemTop(oItem)-1) ? this.getPrevious(oItem) : this.getNext(oItem)) || oItem);
    }

    if (!this.getItemSelected(oItem)) {
      this.renderItemSelectionState(oItem, true);
    }

    // Clear up and add new one
    //this._selectedItems.removeAll();
    this._selectedItems.add(oItem);

    this._addToCurrentSelection = true;
  }


  // ********************************************************************
  //   Mode #2: (De-)Select item range in mouse drag session
  // ********************************************************************
  else if (this._activeDragSession && bOver)
  {
    if (oldLead) {
      this._deselectItemRange(currentAnchorItem, oldLead);
    }

    // Drag down
    if (this.isBefore(currentAnchorItem, oItem))
    {
      if (this._addToCurrentSelection)
      {
        this._selectItemRange(currentAnchorItem, oItem, false);
      }
      else
      {
        this._deselectItemRange(currentAnchorItem, oItem);
      }
    }

    // Drag up
    else
    {
      if (this._addToCurrentSelection)
      {
        this._selectItemRange(oItem, currentAnchorItem, false);
      }
      else
      {
        this._deselectItemRange(oItem, currentAnchorItem);
      }
    }

    // a little bit hacky, but seems to be a fast way to detect if we slide to top or to bottom
    this.scrollItemIntoView((this.getBoundedWidget().getScrollTop() > (this.getItemTop(oItem)-1) ? this.getPrevious(oItem) : this.getNext(oItem)) || oItem);
  }


  // ********************************************************************
  //   Mode #3: Add new item to current selection (ctrl pressed)
  // ********************************************************************
  else if (this.getMultiSelection() && vCtrlKey && !vShiftKey)
  {
    if (!this._activeDragSession) {
      this._addToCurrentSelection = !(this.getCanDeselect() && this.getItemSelected(oItem));
    }

    this.setItemSelected(oItem, this._addToCurrentSelection);
    this.setAnchorItem(oItem);
  }


  // ********************************************************************
  //   Mode #4: Add new (or continued) range to selection
  // ********************************************************************
  else if (this.getMultiSelection() && vCtrlKey && vShiftKey)
  {
    if (!this._activeDragSession) {
      this._addToCurrentSelection = !(this.getCanDeselect() && this.getItemSelected(oItem));
    }

    if (this._addToCurrentSelection)
    {
      this._selectItemRange(currentAnchorItem, oItem, false);
    }
    else
    {
      this._deselectItemRange(currentAnchorItem, oItem);
    }
  }

  // ********************************************************************
  //   Mode #5: Replace selection with new range selection
  // ********************************************************************
  else if (this.getMultiSelection() && !vCtrlKey && vShiftKey)
  {
    if (this.getCanDeselect())
    {
      this._selectItemRange(currentAnchorItem, oItem, true);
    }

    else
    {
      if (oldLead) {
        this._deselectItemRange(currentAnchorItem, oldLead);
      }

      this._selectItemRange(currentAnchorItem, oItem, false);
    }
  }



  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if(oldFireChange && this._hasChanged(oldVal)) {
    this._dispatchChange();
  }
}




/*
---------------------------------------------------------------------------
  KEY EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto.handleKeyDown = function(vDomEvent) {
  this.warn(
    "qx.manager.selection.SelectionManager.handleKeyDown is deprecated! " +
    "Use keypress insted and bind it to the onkeypress event."
  );
  this.handleKeyPress(vDomEvent);
}


/**
 * Handles key event to perform selection and navigation
 *
 * @param vDomEvent (Element) DOM event object
 */
qx.Proto.handleKeyPress = function(vDomEvent)
{
  var oldVal = this._getChangeValue();

  // Temporary disabling of event fire
  var oldFireChange = this.getFireChange();
  this.setFireChange(false);

  // Ctrl+A: Select all
  if (vDomEvent.getKeyIdentifier() == "A" && vDomEvent.getCtrlKey())
  {
    if (this.getMultiSelection())
    {
      this._selectAll();

      // Update lead item to this new last
      // (or better here: first) selected item
      this.setLeadItem(this.getFirst());
    }
  }

  // Default operation
  else
  {
    var aIndex = this.getAnchorItem();
    var itemToSelect = this.getItemToSelect(vDomEvent);

    // this.debug("Anchor: " + (aIndex ? aIndex.getLabel() : "null"));
    // this.debug("ToSelect: " + (itemToSelect ? itemToSelect.getLabel() : "null"));

    if (itemToSelect && this.getItemEnabled(itemToSelect))
    {
      // Update lead item to this new last selected item
      this.setLeadItem(itemToSelect);

      // Scroll new item into view
      this.scrollItemIntoView(itemToSelect);

      // Stop event handling
      vDomEvent.preventDefault();

      // Select a range
      if (vDomEvent.getShiftKey() && this.getMultiSelection())
      {
        // Make it a little bit more failsafe:
        // Set anchor if not given already. Allows us to select
        // a range without any previous selection.
        if (aIndex == null) {
          this.setAnchorItem(itemToSelect);
        }

        // Select new range (and clear up current selection first)
        this._selectItemRange(this.getAnchorItem(), itemToSelect, true);
      }
      else if (!vDomEvent.getCtrlKey())
      {
        // Clear current selection
        this._deselectAll();

        // Update new item to be selected
        this.renderItemSelectionState(itemToSelect, true);

        // Add item to new selection
        this._selectedItems.add(itemToSelect);

        // Update anchor to this new item
        // (allows following shift range selection)
        this.setAnchorItem(itemToSelect);
      }
      else if (vDomEvent.getKeyIdentifier() == "Space")
      {
        if (this._selectedItems.contains(itemToSelect))
        {
          // Update new item to be selected
          this.renderItemSelectionState(itemToSelect, false);

          // Add item to new selection
          this._selectedItems.remove(itemToSelect);

          // Fix anchor item
          this.setAnchorItem(this._selectedItems.getFirst());
        }
        else
        {
          // Clear current selection
          if (!vDomEvent.getCtrlKey() || !this.getMultiSelection()) {
            this._deselectAll();
          }

          // Update new item to be selected
          this.renderItemSelectionState(itemToSelect, true);

          // Add item to new selection
          this._selectedItems.add(itemToSelect);

          // Update anchor to this new item
          // (allows following shift range selection)
          this.setAnchorItem(itemToSelect);
        }
      }
    }
  }

  // Recover change event status
  this.setFireChange(oldFireChange);

  // Dispatch change Event
  if (oldFireChange && this._hasChanged(oldVal)) {
    this._dispatchChange();
  }
}

qx.Proto.getItemToSelect = function(vKeyboardEvent)
{
  // Don't handle ALT here
  if (vKeyboardEvent.getAltKey()) {
    return null;
  }

  // Handle event by keycode
  switch (vKeyboardEvent.getKeyIdentifier())
  {
    case "Home":
      return this.getHome(this.getLeadItem());

    case "End":
      return this.getEnd(this.getLeadItem());


    case "Down":
      return this.getDown(this.getLeadItem());

    case "Up":
      return this.getUp(this.getLeadItem());


    case "Left":
      return this.getLeft(this.getLeadItem());

    case "Right":
      return this.getRight(this.getLeadItem());


    case "PageUp":
      return this.getPageUp(this.getLeadItem()) || this.getHome(this.getLeadItem());

    case "PageDown":
      return this.getPageDown(this.getLeadItem()) || this.getEnd(this.getLeadItem());


    case "Space":
      if (vKeyboardEvent.getCtrlKey()) {
        return this.getLeadItem();
      }
  }

  return null;
}




/*
---------------------------------------------------------------------------
  CHANGE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._dispatchChange = function()
{
  if (!this.getFireChange()) {
    return;
  }

  if (this.hasEventListeners("changeSelection")) {
    this.dispatchEvent(new qx.event.type.DataEvent("changeSelection", this.getSelectedItems()), true);
  }
}

qx.Proto._hasChanged = function(sOldValue) {
  return sOldValue != this._getChangeValue();
}

qx.Proto._getChangeValue = function() {
  return this._selectedItems.getChangeValue();
}






/*
---------------------------------------------------------------------------
  POSITION HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.getHome = function() {
  return this.getFirst();
}

qx.Proto.getEnd = function() {
  return this.getLast();
}

qx.Proto.getDown = function(vItem)
{
  if (!vItem) {
    return this.getFirst();
  }

  return this.getMultiColumnSupport() ? (this.getUnder(vItem) || this.getLast()) : this.getNext(vItem);
}

qx.Proto.getUp = function(vItem)
{
  if (!vItem) {
    return this.getLast();
  }

  return this.getMultiColumnSupport() ? (this.getAbove(vItem) || this.getFirst()) : this.getPrevious(vItem);
}

qx.Proto.getLeft = function(vItem)
{
  if (!this.getMultiColumnSupport()) {
    return null;
  }

  return !vItem ? this.getLast() : this.getPrevious(vItem);
}

qx.Proto.getRight = function(vItem)
{
  if (!this.getMultiColumnSupport()) {
    return null;
  }

  return !vItem ? this.getFirst() : this.getNext(vItem);
}

qx.Proto.getAbove = function(vItem)
{
  throw new Error("getAbove(): Not implemented yet");
}

qx.Proto.getUnder = function(vItem)
{
  throw new Error("getUnder(): Not implemented yet");
}







/*
---------------------------------------------------------------------------
  PAGE HANDLING
---------------------------------------------------------------------------
*/

/*!
Jump a "page" up.

#param vItem[qx.ui.core.Widget]: Relative to this widget
*/
qx.Proto.getPageUp = function(vItem)
{
  var vBoundedWidget = this.getBoundedWidget();
  var vParentScrollTop = vBoundedWidget.getScrollTop();
  var vParentClientHeight = vBoundedWidget.getClientHeight();

  // Find next item
  var newItem;
  var nextItem = this.getLeadItem();
  if (!nextItem) {
    nextItem = this.getFirst();
  }

  // Normally we should reach the status "lead" for the
  // nextItem after two iterations.
  var tryLoops = 0;
  while (tryLoops < 2)
  {
    while (nextItem && (this.getItemTop(nextItem) - this.getItemHeight(nextItem) >= vParentScrollTop)) {
      nextItem = this.getUp(nextItem);
    }

    // This should never occour after the fix above
    if (nextItem == null) {
      break;
    }

    // If the nextItem is not anymore the leadItem
    // Means: There has occured a change.
    // We break here. This is normally the second step.
    if (nextItem != this.getLeadItem())
    {
      // be sure that the top is reached
      this.scrollItemIntoView(nextItem, true);
      break;
    }

    // Update scrolling (this is normally the first step)
    // this.debug("Scroll-Up: " + (vParentScrollTop + vParentClientHeight - 2 * this.getItemHeight(nextItem)));
    vBoundedWidget.setScrollTop(vParentScrollTop - vParentClientHeight - this.getItemHeight(nextItem));

    // Use the real applied value instead of the calulated above
    vParentScrollTop = vBoundedWidget.getScrollTop();

    // Increment counter
    tryLoops++;
  }

  return nextItem;
}

/*!
Jump a "page" down.

#param vItem[qx.ui.core.Widget]: Relative to this widget
*/
qx.Proto.getPageDown = function(vItem)
{
  var vBoundedWidget = this.getBoundedWidget();
  var vParentScrollTop = vBoundedWidget.getScrollTop();
  var vParentClientHeight = vBoundedWidget.getClientHeight();

  // this.debug("Bound: " + (vBoundedWidget._getTargetNode() != vBoundedWidget.getElement()));

  // this.debug("ClientHeight-1: " + vBoundedWidget._getTargetNode().clientHeight);
  // this.debug("ClientHeight-2: " + vBoundedWidget.getElement().clientHeight);

  // Find next item
  var newItem;
  var nextItem = this.getLeadItem();
  if (!nextItem) {
    nextItem = this.getFirst();
  }

  // Normally we should reach the status "lead" for the
  // nextItem after two iterations.
  var tryLoops = 0;
  while (tryLoops < 2)
  {
    // this.debug("Loop: " + tryLoops);
    // this.debug("Info: " + nextItem + " :: " + (this.getItemTop(nextItem) + (2 * this.getItemHeight(nextItem))) + " <> " + (vParentScrollTop + vParentClientHeight));
    // this.debug("Detail: " + vParentScrollTop + ", " + vParentClientHeight);

    // Find next
    while (nextItem && ((this.getItemTop(nextItem) + (2 * this.getItemHeight(nextItem))) <= (vParentScrollTop + vParentClientHeight))) {
      nextItem = this.getDown(nextItem);
    }

    // This should never occour after the fix above
    if (nextItem == null) {
      break;
    }

    // If the nextItem is not anymore the leadItem
    // Means: There has occured a change.
    // We break here. This is normally the second step.
    if (nextItem != this.getLeadItem()) {
      break;
    }

    // Update scrolling (this is normally the first step)
    // this.debug("Scroll-Down: " + (vParentScrollTop + vParentClientHeight - 2 * this.getItemHeight(nextItem)));
    vBoundedWidget.setScrollTop(vParentScrollTop + vParentClientHeight - 2 * this.getItemHeight(nextItem));

    // Use the real applied value instead of the calulated above
    vParentScrollTop = vBoundedWidget.getScrollTop();

    // Increment counter
    tryLoops++;
  }

  //this.debug("Select: " + nextItem._labelObject.getHtml());

  return nextItem;
}










/*
---------------------------------------------------------------------------
  DISPOSE
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (this._selectedItems)
  {
    this._selectedItems.dispose();
    this._selectedItems = null;
  }

  return qx.core.Target.prototype.dispose.call(this);
}
