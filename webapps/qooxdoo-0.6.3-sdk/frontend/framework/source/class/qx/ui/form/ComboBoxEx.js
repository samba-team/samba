/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * David Perez Carmona (david-perez), based on qx.ui.form.ComboBox

************************************************************************ */

/* ************************************************************************

#module(ui_comboboxex)
#require(qx.ui.table.Table)

************************************************************************ */

/**
 * An enhanced combo-box for qooxdoo.
 *
 * <p>Features:</p>
 * <ul>
 * <li>Editable text field</li>
 * <li>Complete key-navigation</li>
 * <li>Mouse wheel navigation</li>
 * <li>Multicolumn display in list</li>
 * <li>If more than one column, headers are automatically shown</li>
 * <li>Can show the ID and/or description of each list item</li>
 * <li>Automatically calculating needed width</li>
 * <li>Popup list always shows full contents, and can be wider than text field</li>
 * <li>Search values through popup dialog</li>
 * <li>Internationalization support of messages (through custom settings)</li>
 * </ul>
 * <p>Pending features:</p>
 * <ul>
 * <li>Images inside the list</li>
 * <li>Autocomplete on key input</li>
 * </ul>
 *
 * @event beforeInitialOpen {qx.event.type.Event}
 */
qx.OO.defineClass('qx.ui.form.ComboBoxEx', qx.ui.layout.HorizontalBoxLayout, function() {
  qx.ui.layout.HorizontalBoxLayout.call(this);

  // ************************************************************************
  //   POPUP
  // ************************************************************************
  var p = this._popup = new qx.ui.popup.Popup;
  p.setAppearance('combo-box-ex-popup');

  // ************************************************************************
  //   LIST
  // ************************************************************************
  this._createList([ this._getComboSetting('idHeader'), this._getComboSetting('descriptionHeader') ]);

  // ************************************************************************
  //   FIELD
  // ************************************************************************
  var f = this._field = new qx.ui.form.TextField;
  f.setAppearance('combo-box-ex-text-field');
  f.addEventListener("input", this._oninput, this);
  this.add(f);
  this.setEditable(false);

  // ************************************************************************
  //   BUTTON
  // ************************************************************************

  // Use qx.ui.basic.Atom instead of qx.ui.form.Button here to omit the registration
  // of the unneeded and complex button events.
  var b = this._button = new qx.ui.basic.Atom(null, "widget/arrows/down.gif");
  b.set({
    appearance: "combo-box-button",
    tabIndex: -1
  });
  this.add(b);

  // ************************************************************************
  //   BEHAVIOR
  // ************************************************************************
  this.setTabIndex(1);

  // ************************************************************************
  //   WIDGET MOUSE EVENTS
  // ************************************************************************
  this.addEventListener("mousedown", this._onmousedown);
  this.addEventListener("mouseup", this._onmouseup);
  this.addEventListener("mousewheel", this._onmousewheel);
  this.addEventListener("dblclick", function() {
    if (this.getAllowSearch()) {
      this.openSearchDialog();
    }
  });

  // ************************************************************************
  //   WIDGET KEY EVENTS
  // ************************************************************************
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keypress", this._onkeypress);

  // ************************************************************************
  //   WIDGET STATE EVENTS
  // ************************************************************************
  this.addEventListener("beforeDisappear", this._testClosePopup);

  // ************************************************************************
  //   CHILDREN EVENTS
  // ************************************************************************
  this._popup.addEventListener("appear", this._onpopupappear, this);
});

/*
---------------------------------------------------------------------------
  LOCALIZATION SUPPORT
---------------------------------------------------------------------------
*/

qx.Settings.setDefault('titleSearch', 'Search items in list');
qx.Settings.setDefault('toolTipSearchNext', 'Search next occurrence');
qx.Settings.setDefault('idHeader', 'ID');
qx.Settings.setDefault('descriptionHeader', 'Description');
qx.Settings.setDefault('caseSensitiveCaption', 'Case sensitive');


/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "combo-box-ex" });

/*!Is the text field component editable or the user can only select from the list?*/
qx.OO.addProperty({ name: "editable", type: "boolean", getAlias: "isEditable" });

/*!0 based. -1 means no selected index.  It retrieves always the value column of the selection, not the description.*/
qx.OO.addProperty({ name: "value", type : "string" });

/*!How many items to transverse with PageUp and PageDn.*/
qx.OO.addProperty({ name: "pagingInterval", type: "number", defaultValue: 10 });

/*!Show the ID column (column 0) of the selection data?*/
qx.OO.addProperty({ name: "idColumnVisible", type: "boolean", getAlias: "isIdColumnVisible", defaultValue: false });

/*!Only used when editable is false.  It determines what to show in the text field of the combo box.*/
qx.OO.addProperty({ name: "showOnTextField", type: "string", defaultValue: 'description', possibleValues : [ 'description', 'idAndDescription'  ] });

/*!Only used when editable is false and showOnTextField=='idAndDescription'.*/
qx.OO.addProperty({ name: "idDescriptionSeparator", type: "string", defaultValue: '- ' });

/*!Ensures that always an item is selected (in case the selection isn't empty). Only used when editable is false.*/
qx.OO.addProperty({ name: 'ensureSomethingSelected', type: "boolean", defaultValue: true });

/*!Allow the search dialog when double clicking the combo, or pressing special keys?.*/
qx.OO.addProperty({ name: 'allowSearch', type: "boolean", defaultValue: true });

/*!Maximum number of visible rows in the popup list.*/
qx.OO.addProperty({ name: 'maxVisibleRows', type: "number", defaultValue: 10 });


/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getPopup = function() {
  return this._popup;
}

qx.Proto.getList = function() {
  return this._list;
}

qx.Proto.getField = function() {
  return this._field;
}

qx.Proto.getButton = function() {
  return this._button;
}

qx.Proto._getComboSetting = function(key) {
  return qx.Settings.getValueOfClass('qx.ui.form.ComboBoxEx', key);
}

/**Gets the current selected row of the selection.
 * @return null if nothing selected or an array*/
qx.Proto.getSelectedRow = function() {
  var ind = this.getSelectedIndex();
  return ind < 0 ? null : this._model.getData()[ind];
}

/**Creates the list component.*/
qx.Proto._createList = function(columns) {
  this._model = new qx.ui.table.SimpleTableModel;
  // Default column titles
  this._model.setColumns(columns);
  var l = this._list = new qx.ui.table.Table(this._model);
  l.setFocusedCell = function() {}
  l.setAppearance('combo-box-ex-list');
  // We receive this: Modification of property "keepFirstVisibleRowComplete" failed with exception: TypeError - vCurrentChild has no properties or
  // this: Modification of property "keepFirstVisibleRowComplete" failed with exception: TypeError - this.getParent() has no properties
  l.forceKeepFirstVisibleRowComplete(false);
  var selMan = l._getSelectionManager();
  var oldHandle = selMan.handleMouseUp, me = this;
  selMan.handleMouseUp = function(vItem, e) {
    oldHandle.apply(selMan, arguments);
    if (e.isLeftButtonPressed()) {
    me._testClosePopup();
    }
  }
  this._modifyIdColumnVisible(this.getIdColumnVisible());
  this._manager = l.getSelectionModel();
  this._manager.addEventListener('changeSelection', this._onChangeSelection, this);
  // Avoid deselection from user
  this._manager.removeSelectionInterval = function() {};
  this._manager.setSelectionMode(qx.ui.table.SelectionModel.SINGLE_SELECTION);
  this._popup.add(l);
  // Invalidate calculation of column widths
  delete this._calcDimensions;
}


/*
---------------------------------------------------------------------------
  PSEUDO-PROPERTIES
---------------------------------------------------------------------------
*/

/**Sets the header for each column.
 * @param columns {String[]}*/
qx.Proto.setColumnHeaders = function(columns) {
  if (!this._list || columns.length != this._model.getColumnCount()) {
    if (this._list) {
      var data = this._model.getData();
      this._list.setParent(null);
      this._list.dispose();
      this._list = null;
    }
    this._createList(columns);
    if (data && data.length) {
      this._model.setData(data);
    }
  } else {
    this._model.setColumns(columns);
    this._list.getTableColumnModel().init(columns.length);
    delete this._calcDimensions;
  }
  this._modifyIdColumnVisible(this.getIdColumnVisible());
}

/**Getter for {@link #setColumnHeaders}.
 * @return {String[]}*/
qx.Proto.getColumnHeaders = function(propVal) {
  var cols = [];
  cols.length = this._model.getColumnCount();
  for (var col = 0; col < cols.length; col++) {
    cols[col] = this._model.getColumnName(col);
  }
  return cols;
}

/**Sets the list of selectable items.
 * @param data {var[][]} Array of values.  Its value is an array, with the following info:<ul>.
 * <li>Column 0 represents the ID, i.e. the value that is stored internally and used by the app.</li>
 * <li>Column 1 represents the description, the text that the end user normally sees.</li>
 * <li>Columns > 1 will also be shown in the popup list, it you have set the appropiate column headers with {@link #setColumnHeaders}.</li>
 * </ul>*/
qx.Proto.setSelection = function(data) {
  // Invalidate calculation of column widths
  delete this._calcDimensions;
  this._model.setData(data);
  // Try to preserve currently selected value
  if (!this.getEditable()) {
    this._modifyValue(this.getValue());
  }
}

/**Getter for {@link #setSelection}.
 * @return {Array}*/
qx.Proto.getSelection = function() {
  return this._model.getData();
}

/**Sets the index of the currently selected item in the list.
 * @param index {Number} -1 means no selected index*/
qx.Proto.setSelectedIndex = function(index) {
  var items = this.getSelection().length;
  if (items >= 0) {
    if (index < 0 && !this.getEditable() && this.getEnsureSomethingSelected()) {
      index = 0;
    }
    if (index >= 0) {
      index = qx.lang.Number.limit(index, 0, items-1);
      this._manager.setSelectionInterval(index, index);
      if (this._popup.isSeeable()) {
        this._list.scrollCellVisible(0, index);
      }
    } else {
      this._manager.clearSelection();
    }
  }
  return true;
}

/**Getter for {@link #setSelectedIndex}.*/
qx.Proto.getSelectedIndex = function() {
  var index = this._manager.getAnchorSelectionIndex();
  return this._manager.isSelectedIndex(index) ? index:-1;
}


/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyShowOnTextField = function(propVal) {
  if (!this.getEditable()) {
    this.setSelectedIndex(this.getSelectedIndex());
    delete this._calcDimensions;  // Invalidate this._neededTextFieldWidth
  }
  return true;
}

qx.Proto._modifyMaxVisibleRows = function() {
  delete this._calcDimensions;  // Invalidate this._list.height
  return true;
}

qx.Proto._checkIdDescriptionSeparator = function(propVal) {
  // For measuring widths, it is better to replace spaces with non-breakable spaces
  return String(propVal).replace(/ /g, '\u00A0')
}

qx.Proto._modifyIdDescriptionSeparator = function(propVal) {
  if (!this.getEditable() && this.getShowOnTextField() == 'idAndDescription') {
    this.setSelectedIndex(this.getSelectedIndex());
    delete this._calcDimensions;  // Invalidate this._neededTextFieldWidth
  }
  return true;
}

qx.Proto._modifyIdColumnVisible = function(propVal) {
  this._list.getTableColumnModel().setColumnVisible(0, propVal);
  delete this._calcDimensions;
  return true;
}

qx.Proto._modifyEditable = function(propValue/*, propOldValue, propData*/) {
  var f = this._field;
  f.setReadOnly(!propValue);
  f.setCursor(propValue ? null : "default");
  f.setSelectable(propValue);
  return true;
}

qx.Proto._modifyValue = function(propValue/*, propOldValue, propData*/) {
  this._fromValue = true;

  var values = this._model.getData();
  var i = -1;
  if (propValue != null) {
    for (var i = 0; i < values.length; i++) {
      if (propValue == values[i][0]) {
        break;
      }
    }
    if (i == values.length) {
      i = -1;
    }
  }
  if (this.getEditable()) {
    this._field.setValue(propValue);
  }
  // only do this if we called setValue separately
  // and not from the property "selected".
  if (!this._fromSelected) {
    this.setSelectedIndex(i);
  }
  // reset hint
  delete this._fromValue;
  return true;
}

qx.Proto._modifyEnabled = function(propValue/*, propOldValue, propData*/) {
  if (this._button) {
    this._button.setEnabled(propValue);
  }
  if (this._field) {
    this._field.setEnabled(propValue);
  }
  return qx.ui.layout.HorizontalBoxLayout.prototype._modifyEnabled.apply(this, arguments);
}


/*
---------------------------------------------------------------------------
  POPUP HELPER
---------------------------------------------------------------------------
*/

qx.Proto._oldSelected = null;

qx.Proto._openPopup = function() {
  if (this.isSearchInProgress()) {
    return;
  }
  var p = this._popup;
  p.setAutoHide(false);
  var el = this.getElement();
  if (!p.isCreated()) {
    this.createDispatchEvent("beforeInitialOpen");
  }
  if (!this.getSelection().length) {
    return;
  }
  p.positionRelativeTo(el, 1, qx.dom.Dimension.getBoxHeight(el));
  this._calculateDimensions();
  p.setParent(this.getTopLevelWidget());
  p.auto();
  p.show();
  this._oldSelected = this.getSelectedIndex();
  window.setInterval(function() {
    p.setAutoHide(true);
  }, 0);
}

/**Hide the popup list.*/
qx.Proto._closePopup = function() {
  this._popup.hide();
}

/**Hide the popup list only when needed.*/
qx.Proto._testClosePopup = function() {
  if (this._popup.isSeeable()) {
    this._closePopup();
  }
}

/**Toggle the visibility of the popup list.*/
qx.Proto._togglePopup = function() {
  this._popup.isSeeable() ? this._closePopup() : this._openPopup();
}

/*
---------------------------------------------------------------------------
  DIMENSIONING
---------------------------------------------------------------------------
*/

/**Sizes the width of the text field component to the needed value to show any selection item.*/
qx.Proto.sizeTextFieldToContent = function() {
  this._calculateDimensions();
  this._field.setWidth(this._neededTextFieldWidth);
}

/**Calculates the needed dimensions for the text field and list components*/
qx.Proto._calculateDimensions = function() {
  if (this._calcDimensions) {
    // Already calculated
    return;
  }
  var data = this.getSelection();
  var cols = this.getColumnHeaders(), nCols = cols.length;
  var columnWidths = [];
  this._neededTextFieldWidth = 0;
  columnWidths.length = cols.length;
  for (var col = 0; col < cols.length; col++) {
    columnWidths[col] = 0;
  }
  var withDescript = this.getShowOnTextField() == 'idAndDescription';
  for (var row = 0, rows = Math.min(data.length, 50); row < rows; row++) {
    var r = data[row], wi0, wi1;
    for (col = 0; col < nCols; col++) {
      var wi = this._getTextWidth(r[col]);
      if (col == 0) {
        wi0 = wi;
      } else if (col == 1) {
        wi1 = wi;
      }
      columnWidths[col] = Math.max(wi, columnWidths[col]);
    }
    this._neededTextFieldWidth = Math.max(this._neededTextFieldWidth,
      wi1+(withDescript ? wi0:0));
  }
  if (this.getShowOnTextField() == 'idAndDescription') {
    this._neededTextFieldWidth += this._getTextWidth(this.getIdDescriptionSeparator());
  }
  this._neededTextFieldWidth += 8;  /*Extra margins*/
  var maxRows = this.getMaxVisibleRows(),
    // Only assign room for the vertical scrollbar when needed
    width = data.length > maxRows ? (new qx.ui.core.ScrollBar)._getScrollBarWidth():0,
    colModel = this._list.getTableColumnModel(),
    countVisible = 0;

  // ##Only show headers if we have more than 1 column visible
  for (col = 0; col < nCols; col++) {
    if (colModel.isColumnVisible(col)) {
      countVisible++;
    }
  }
  var hasHeaders = countVisible > 1;
  this._list.getPaneScroller(0).getHeader().setHeight(hasHeaders ? 'auto' : 1);

  // ##Size each column
  for (col = 0; col < nCols; col++) {
    if (colModel.isColumnVisible(col)) {
      var w = columnWidths[col];
      if (hasHeaders) {
        w = Math.max(w, this._getTextWidth(cols[col]));
      }
      w += 8;
      this._list.setColumnWidth(col, w);
      width += w;
    }
  }

  // ##Final width and height
  this._list.set({
    width: width,
    height: this._list.getRowHeight()*
      Math.min(maxRows, (hasHeaders ? 1:0)+data.length)+2+(hasHeaders ? 2:0)
  });
  // This denotes dimensions are already calculated
  this._calcDimensions = true;
}

/**Calculates the width of the given text.
 * The default font is used.
 * @return {integer}*/
qx.Proto._getTextWidth = function(text) {
  var lab = new qx.ui.basic.Label(text);
  var res = lab.getPreferredBoxWidth();
  lab.dispose();
  return res;
}


/*
---------------------------------------------------------------------------
  SEARCHING
---------------------------------------------------------------------------
*/

/**Does this combo have the searched dialog open?*/
qx.Proto.isSearchInProgress = function() {
  return !this._popup.contains(this._list);
}

/**Searches the given text.  Called from the search dialog.
 * @param startIndex  {Number} Start index, 0 based
 * @param txt      {String} Text to find
 * @param caseSens    {Boolean} Case sensivity flag.*/
qx.Proto._search = function(startIndex, txt, caseSens) {
  if (txt == null || !txt.length) {
    return;
  }
  var row = startIndex,
    nCols = this._model.getColumnCount(),
    nRows = this.getSelection().length,
    data = this._model.getData();
  if (!caseSens) {
    txt = txt.toLowerCase();
  }
  var colModel = this._list.getTableColumnModel();
  while (true) {
    var dataRow = data[row];
    if (dataRow) {
    for (var col = 0; col < nCols; col++) {
      if (colModel.isColumnVisible(col)) {
        var txtCol = dataRow[col];
        if (!caseSens) {
          txtCol = txtCol.toLowerCase();
        }
        if (txtCol.indexOf(txt) >= 0) {
          this._manager.setSelectionInterval(row, row);
          this._list.scrollCellVisible(1, row);
          return;
        }
      }
    }
    }
    row = (row+1)% nRows;
    if (row == startIndex) {
      break;
    }
  }
}

/**Opens a popup search dialog, useful when the combo has a lot of items.
 * This dialog is triggered by double clicking the combo, pressing F3 or Ctrl+F.*/
qx.Proto.openSearchDialog = function() {
  var sel = this.getSelection();
  if (!sel || !sel.length || this.isSearchInProgress()) {
    return;
  }
  this._testClosePopup();

  var me = this,
    oldSelectedIndex = this.getSelectedIndex(),
    startIndex = oldSelectedIndex;

  //###searchField
  function search() {
    me._search(startIndex, searchField.getComputedValue(), checkCase.isChecked());
  }
  var searchField = new qx.ui.form.TextField;
  searchField.set({
    minWidth: this._field.getWidth(),
    width: '100%'
  });
  searchField.addEventListener("input", function() {
    search();
  });

  //###checkCase
  var checkCase = new qx.ui.form.CheckBox(this._getComboSetting('caseSensitiveCaption'));
  checkCase.set({
    horizontalAlign: 'center',
    marginBottom: 4
  });

  //###vbox
  var vbox = new qx.ui.layout.VerticalBoxLayout;
  vbox.set({
    spacing: 6,
    horizontalChildrenAlign: 'center',
    height: '100%'
  });
  vbox.auto();
  vbox.add(searchField, checkCase);

  //###list, we reuse the same list in the popup
  this._calculateDimensions();
  var border = qx.renderer.border.BorderPresets.getInstance().inset;
  var newListSettings = {
    /*minHeight: border.getTopWidth()+this._list.getHeight()+border.getBottomWidth(),
    height: '1*',*/
    height: border.getTopWidth()+this._list.getHeight()+border.getBottomWidth(),
    width: border.getLeftWidth()+this._list.getWidth()+border.getRightWidth(),
    border: border,
    parent: vbox
  };
  // Save old list settings
  var oldListSettings = {};
  for (var prop in newListSettings) {
    oldListSettings[prop] = this._list[qx.OO.getter[prop]]();
  }
  this._list.set(newListSettings);

  //###buttons
  var butNext = new qx.ui.form.Button('', 'icon/16/find.png');
  butNext.set({
    toolTip: new qx.ui.popup.ToolTip(this._getComboSetting('toolTipSearchNext'))
  });
  butNext.addEventListener("execute", function() {
    startIndex = (this.getSelectedIndex()+1) % sel.length;
    search();
  }, this);

  var butOk = new qx.ui.form.Button('', 'icon/16/button-ok.png');
  butOk.addEventListener('execute', function() {
    oldSelectedIndex = null;
    win.close();
  }, this);

  var butCancel = new qx.ui.form.Button('', 'icon/16/button-cancel.png');
  butCancel.addEventListener('execute', function() {
    win.close();
  }, this);

  var butBox = new qx.ui.layout.VerticalBoxLayout;
  butBox.auto();
  butBox.set({
    spacing: 10
  });
  butBox.add(butNext, butOk, butCancel);

  //###hbox
  var hbox = new qx.ui.layout.BoxLayout;
  hbox.auto();
  hbox.setPadding(10);
  hbox.set({
    spacing: 8,
    minHeight: 'auto',
    height: '100%'
  });
  hbox.add(vbox, butBox);

  //###Window
  var win = new qx.ui.window.Window(this._getComboSetting('titleSearch'), 'icon/16/find.png');
  win.add(hbox);
  win.positionRelativeTo(this);
  win.set({
    autoHide: true,
    allowMaximize: false,
    showMaximize: false,
    allowMinimize: false,
    showMinimize: false
  });
  win.addEventListener("appear", function() {
    searchField.focus();
  });
  win.addEventListener("disappear", function() {
    if (oldSelectedIndex != null) {
      // Hit Cancel button
      this.setSelectedIndex(oldSelectedIndex);
    }
    this._list.set(oldListSettings);
    this.focus();
  }, this);
  win.addEventListener("keydown", function(e) {
    switch (e.getKeyIdentifier()) {
      case "Enter":
        butOk.createDispatchEvent('execute');
        break;
      case "Escape":
        butCancel.createDispatchEvent('execute');
        break;
      case "F3":
        butNext.createDispatchEvent('execute');
        break;
      default:
        return;
    }
    e.preventDefault();
  }, this);
  win.auto();
  win.addToDocument();
  win.open();
}

/*
---------------------------------------------------------------------------
  OTHER EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onChangeSelection = function(e) {
  this._fromSelected = true;

  // only do this if we called setValue separately
  // and not from the event "input".
  if (!this._fromInput) {
    var index = this.getSelectedIndex();
    if (index >= 0) {
      var row = this._model.getData()[index];
    }
    if (row || !this.getEditable()) {
      this.setValue(row && row[0]);
    }
    // In case of editable, this.setValue() already calls this._field.setValue()
    if (!this.getEditable()) {
      var val = "";
      if (row) {
        val = this.getShowOnTextField() == 'description' ?
          row[1] :
          (row[0] != null && row[0] != '' ? row[0] + this.getIdDescriptionSeparator() + row[1]:row[1]);
      }
      this._field.setValue(val);
    }
  }
  // reset hint
  delete this._fromSelected;
}

qx.Proto._onpopupappear = function(e) {
  var index = this.getSelectedIndex();
  if (index >= 0) {
    this._list.scrollCellVisible(0, index);
  }
}

qx.Proto._oninput = function(e) {
  // Hint for modifier
  this._fromInput = true;
  this.setValue(this._field.getComputedValue());
  delete this._fromInput;
}


/*
---------------------------------------------------------------------------
  MOUSE EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onmousedown = function(e) {
  switch(e.getTarget()) {
    case this._field:
      if (this.getEditable()) {
        break;
      }
      // no break here
    case this._button:
      this._button.addState("pressed");
      this._togglePopup();
      // Assure we receive the mouse up event
      this.setCapture(true);
      break;
  }
}

qx.Proto._onmouseup = function(e) {
  switch(e.getTarget()) {
    case this._field:
      if (this.getEditable()) {
        break;
      }
      // no break here
    default:
      this._button.removeState("pressed");
      break;
  }
  this.setCapture(false);
}

qx.Proto._onmousewheel = function(e) {
  if (!this._popup.isSeeable()) {
    this.setSelectedIndex(Math.max(0, this.getSelectedIndex()+(e.getWheelDelta() < 0 ? -1:1)));
  }
}


/*
---------------------------------------------------------------------------
  KEY EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onkeydown = function(e) {
  var vVisible = this._popup.isSeeable();

  switch (e.getKeyIdentifier()) {
    case "Enter":
      if (vVisible) {
        this._closePopup();
        this.setFocused(true);
      } else {
        this._openPopup();
      }
      break;

    case "Escape":
      if (vVisible) {
        this.setSelectedIndex(this._oldSelected);
        this._closePopup();
        this.setFocused(true);
      }
      break;

    case "Home":
      this.setSelectedIndex(0);
      break;

    case "End":
      var items = this.getSelection().length;
      if (items) {
        this.setSelectedIndex(items-1);
      }
      break;

    case "Down":
      if (e.getAltKey()) {
        this._togglePopup();
      }
      break;

    case "F3":
      if (this.getAllowSearch()) {
        this.openSearchDialog();
      }
      break;

    case "F":
      if (e.getCtrlKey()) {
        if (this.getAllowSearch()) {
          this.openSearchDialog();
        }
        break;
      }
      return;

    default:
      if (vVisible) {
        this._list.dispatchEvent(e);
      }
      return;
  }
  e.preventDefault();
}


qx.Proto._onkeypress = function(e) {
  var vVisible = this._popup.isSeeable();

  switch (e.getKeyIdentifier()) {
    case "Up":
      this.setSelectedIndex(Math.max(0, this.getSelectedIndex()-1));
      break;

    case "Down":
      this.setSelectedIndex(Math.max(0, this.getSelectedIndex()+1));
      break;

    case "PageUp":
      this.setSelectedIndex(Math.max(0, this.getSelectedIndex()-this.getPagingInterval()));
      break;

    case "PageDown":
      this.setSelectedIndex(this.getSelectedIndex()+this.getPagingInterval());
      break;

    default:
      if (vVisible) {
        this._list.dispatchEvent(e);
      }
      return;
  }
  e.preventDefault();

  if (!this.isEditable() && this._list.isSeeable()) {
    this._list.dispatchEvent(e);
  }

}


/*
---------------------------------------------------------------------------
  FOCUS HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._visualizeBlur = function() {
  // Force blur, even if mouseFocus is not active because we
  // need to be sure that the previous focus rect gets removed.
  // But this only needs to be done, if there is no new focused element.
  if (qx.sys.Client.getInstance().isMshtml()) {
    if (this.getEnableElementFocus() && !this.getFocusRoot().getFocusedChild()) {
      try {
        if (this.getEditable())  {
          this.getField().getElement().blur();
        } else {
          this.getElement().blur();
        }
      }
      catch(ex) {};
    }
  } else {
    if (this.getEnableElementFocus()) {
      try {
        if (this.getEditable()) {
          this.getField().getElement().blur();
        } else if (!this.getFocusRoot().getFocusedChild()) {
          this.getElement().blur();
        }
      }
      catch(ex) {};
    }
  }
  this.removeState("focused");
  return true;
}

qx.Proto._visualizeFocus = function() {
  if (!qx.event.handler.FocusHandler.mouseFocus && this.getEnableElementFocus()) {
    try {
      if (this.getEditable()) {
        this.getField().getElement().focus();
        this.getField()._ontabfocus();
      } else {
        this.getElement().focus();
      }
    } catch(ex) {
    }
  }
  this.addState("focused");
  return true;
}

/*
---------------------------------------------------------------------------
  DISPOSE
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function() {
  if (this.getDisposed()) {
    return;
  }

  // ************************************************************************
  //   WIDGET MOUSE EVENTS
  // ************************************************************************
  this.removeEventListener("mousedown", this._onmousedown);
  this.removeEventListener("mouseup", this._onmouseup);
  this.removeEventListener("mousewheel", this._onmousewheel);


  // ************************************************************************
  //   WIDGET KEY EVENTS
  // ************************************************************************
  this.removeEventListener("keydown", this._onkeydown);
  this.removeEventListener("keypress", this._onkeypress);


  this._model = null;
  if (this._manager) {
    this._manager.removeEventListener('changeSelection', this._onChangeSelection);
    this._manager = null;
  }
  if (this._list) {
    this._list.dispose();
    this._list = null;
  }
  if (this._popup) {
    this._popup.removeEventListener("appear", this._onpopupappear, this);
    this._popup.dispose();
    this._popup = null;
  }
  if (this._field) {
    if (this.getEditable()) {
      this._field.removeEventListener("input", this._oninput, this);
    }
    this._field.dispose();
    this._field = null;
  }
  if (this._button) {
    this._button.dispose();
    this._button = null;
  }
  return qx.ui.layout.HorizontalBoxLayout.prototype.dispose.call(this);
}
