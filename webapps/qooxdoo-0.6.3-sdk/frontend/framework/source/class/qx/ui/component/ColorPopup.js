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



************************************************************************ */

/*!
  A color popup
*/
qx.OO.defineClass("qx.ui.component.ColorPopup", qx.ui.popup.Popup,
function(tables)
{
  qx.ui.popup.Popup.call(this);

  this.setPadding(4);
  this.auto();
  this.setBorder(qx.renderer.border.BorderPresets.getInstance().outset);
  this.setBackgroundColor("threedface");

  this._tables = tables;

  this._createLayout();
  this._createAutoBtn();
  this._createBoxes();
  this._createPreview();
  this._createSelectorBtn();

  this.addEventListener("beforeAppear", this._onBeforeAppear);
});

qx.OO.addProperty({ name : "value", type : "object", instance : "qx.renderer.color.Color" });

qx.OO.addProperty({ name : "red", type : "number", defaultValue : 0 });
qx.OO.addProperty({ name : "green", type : "number", defaultValue : 0 });
qx.OO.addProperty({ name : "blue", type : "number", defaultValue : 0 });

qx.Proto._minZIndex = 1e5;





/*
---------------------------------------------------------------------------
  CREATOR SUBS
---------------------------------------------------------------------------
*/

qx.Proto._createLayout = function()
{
  this._layout = new qx.ui.layout.VerticalBoxLayout;
  this._layout.setLocation(0, 0);
  this._layout.auto();
  this._layout.setSpacing(2);

  this.add(this._layout);
}

qx.Proto._createAutoBtn = function()
{
  this._automaticBtn = new qx.ui.form.Button("Automatic");
  this._automaticBtn.setWidth(null);
  this._automaticBtn.setAllowStretchX(true);
  this._automaticBtn.addEventListener("execute", this._onAutomaticBtnExecute, this);

  this._layout.add(this._automaticBtn);
}

qx.Proto._recentTableId = "recent";
qx.Proto._fieldWidth = 14;
qx.Proto._fieldHeight = 14;
qx.Proto._fieldNumber = 12;

qx.Proto._createBoxes = function()
{
  this._boxes = {};

  var tables = this._tables;
  var table, box, boxLayout, field;

  for (var tableId in tables)
  {
    table = tables[tableId];

    box = new qx.ui.groupbox.GroupBox(table.label);
    box.setHeight("auto");

    this._boxes[tableId] = box;
    this._layout.add(box);

    boxLayout = new qx.ui.layout.HorizontalBoxLayout;
    boxLayout.setLocation(0, 0);
    boxLayout.setSpacing(1);
    boxLayout.auto();
    box.add(boxLayout);

    for (var i=0; i<this._fieldNumber; i++)
    {
      field = new qx.ui.basic.Terminator;

      field.setBorder(qx.renderer.border.BorderPresets.getInstance().thinInset);
      field.setBackgroundColor(table.values[i] || null);
      field.setDimension(this._fieldWidth, this._fieldHeight);

      field.addEventListener("mousedown", this._onFieldMouseDown, this);
      field.addEventListener("mouseover", this._onFieldMouseOver, this);

      boxLayout.add(field);
    }
  }
}

qx.Proto._createPreview = function()
{
  this._previewBox = new qx.ui.groupbox.GroupBox("Preview (Old/New)");
  this._previewLayout = new qx.ui.layout.HorizontalBoxLayout;
  this._selectedPreview = new qx.ui.basic.Terminator;
  this._currentPreview = new qx.ui.basic.Terminator;

  this._previewLayout.setHeight("auto");
  this._previewLayout.setWidth("100%");
  this._previewLayout.setSpacing(4);
  this._previewLayout.add(this._selectedPreview, this._currentPreview);

  this._previewBox.setHeight("auto");
  this._previewBox.add(this._previewLayout);

  this._layout.add(this._previewBox);

  this._selectedPreview.setBorder(qx.renderer.border.BorderPresets.getInstance().inset);
  this._selectedPreview.setWidth("1*");
  this._selectedPreview.setHeight(24);

  this._currentPreview.setBorder(qx.renderer.border.BorderPresets.getInstance().inset);
  this._currentPreview.setWidth("1*");
  this._currentPreview.setHeight(24);
}

qx.Proto._createSelectorBtn = function()
{
  this._selectorButton = new qx.ui.form.Button("Open ColorSelector");
  this._selectorButton.setWidth(null);
  this._selectorButton.setAllowStretchX(true);
  this._selectorButton.addEventListener("execute", this._onSelectorButtonExecute, this);

  this._layout.add(this._selectorButton);
}

qx.Proto._createColorSelector = function()
{
  if (this._colorSelector) {
    return;
  }

  this._colorSelectorWindow = new qx.ui.window.Window("Color Selector");
  this._colorSelectorWindow.setMinWidth(null);
  this._colorSelectorWindow.setMinHeight(null);
  this._colorSelectorWindow.setResizeable(false);
  this._colorSelectorWindow.auto();

  this._colorSelector = new qx.ui.component.ColorSelector;
  this._colorSelector.setBorder(null);
  this._colorSelector.setLocation(0, 0);
  this._colorSelector.addEventListener("dialogok", this._onColorSelectorOk, this);
  this._colorSelector.addEventListener("dialogcancel", this._onColorSelectorCancel, this);

  this._colorSelectorWindow.add(this._colorSelector);
  this._colorSelectorWindow.addToDocument();
}







/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyValue = function(propValue, propOldValue, propData)
{
  if (propValue === null)
  {
    this.setRed(null);
    this.setGreen(null);
    this.setBlue(null);
  }
  else
  {
    this.setRed(propValue.getRed());
    this.setGreen(propValue.getGreen());
    this.setBlue(propValue.getBlue());
  };

  this._selectedPreview.setBackgroundColor(propValue);
  this._rotatePreviousColors();

  return true;
}

qx.Proto._rotatePreviousColors = function()
{
  var vRecentTable = this._tables[this._recentTableId].values;
  var vRecentBox = this._boxes[this._recentTableId];

  if (!vRecentTable) {
    return;
  }

  var newValue = this.getValue();

  if (!newValue) {
    return;
  }

  // use style compatible value (like the incoming value from the user or as RGB value string)
  newValue = newValue.getStyle();

  // Modifying incoming table
  var vIndex = vRecentTable.indexOf(newValue);

  if (vIndex != -1) {
    qx.lang.Array.removeAt(vRecentTable, vIndex);
  } else if (vRecentTable.length == this._fieldNumber) {
    vRecentTable.shift();
  }

  vRecentTable.push(newValue);

  // Sync to visible fields
  var vFields = vRecentBox.getFrameObject().getFirstChild().getChildren();
  for (var i=0; i<vFields.length; i++) {
    vFields[i].setBackgroundColor(vRecentTable[i] || null);
  }
}






/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onFieldMouseDown = function(e) {
  this.setValue(this._currentPreview.getBackgroundColor());
}

qx.Proto._onFieldMouseOver = function(e) {
  this._currentPreview.setBackgroundColor(e.getTarget().getBackgroundColor());
}

qx.Proto._onAutomaticBtnExecute = function(e) {
  this.setValue(null);
  this.hide();
}

qx.Proto._onSelectorButtonExecute = function(e)
{
  this._createColorSelector();

  this._colorSelectorWindow.setTop(qx.dom.Location.getPageBoxTop(this._selectorButton.getElement()) + 10);
  this._colorSelectorWindow.setLeft(qx.dom.Location.getPageBoxLeft(this._selectorButton.getElement()) + 100);

  this.hide();

  this._colorSelectorWindow.open();
}

qx.Proto._onColorSelectorOk = function(e)
{
  var sel = this._colorSelector;
  this.setValue(qx.renderer.color.ColorCache([sel.getRed(), sel.getGreen(), sel.getBlue()]));
  this._colorSelectorWindow.close();
}

qx.Proto._onColorSelectorCancel = function(e) {
  this._colorSelectorWindow.close();
}

qx.Proto._onBeforeAppear = function(e) {
  this._currentPreview.setBackgroundColor(null);
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

  this._tables = null;
  this._boxes = null;

  if (this._layout)
  {
    this._layout.dispose();
    this._layout = null;
  }

  if (this._automaticBtn)
  {
    this._automaticBtn.dispose();
    this._automaticBtn = null;
  }

  if (this._previewBox)
  {
    this._previewBox.dispose();
    this._previewBox = null;
  }

  if (this._previewLayout)
  {
    this._previewLayout.dispose();
    this._previewLayout = null;
  }

  if (this._selectedPreview)
  {
    this._selectedPreview.dispose();
    this._selectedPreview = null;
  }

  if (this._currentPreview)
  {
    this._currentPreview.dispose();
    this._currentPreview = null;
  }

  if (this._selectorButton)
  {
    this._selectorButton.dispose();
    this._selectorButton = null;
  }

  if (this._colorSelectorWindow)
  {
    this._colorSelectorWindow.dispose();
    this._colorSelectorWindow = null;
  }

  if (this._colorSelector)
  {
    this._colorSelector.dispose();
    this._colorSelector = null;
  }

  return qx.ui.popup.Popup.prototype.dispose.call(this);
}
