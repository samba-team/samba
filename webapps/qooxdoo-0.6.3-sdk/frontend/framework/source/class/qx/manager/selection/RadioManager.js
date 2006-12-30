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

/*!
  Each instance manage vItems set of radio options: qx.ui.form.RadioButton, qx.ui.toolbar.RadioButton, ...
*/
qx.OO.defineClass("qx.manager.selection.RadioManager", qx.core.Target,
function(vName, vMembers)
{
  // we don't need the manager data structures
  qx.core.Target.call(this);

  // create item array
  this._items = [];

  // apply name property
  this.setName(qx.util.Validation.isValidString(vName) ? vName : qx.manager.selection.RadioManager.AUTO_NAME_PREFIX + this._hashCode);

  if (qx.util.Validation.isValidArray(vMembers)) {
    // add() iterates over arguments, but vMembers is an array
    this.add.apply(this, vMembers);
  }
});

qx.manager.selection.RadioManager.AUTO_NAME_PREFIX = "qx-radio-";




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "selected" });
qx.OO.addProperty({ name : "name", type : "string" });






/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getItems = function() {
  return this._items;
}

qx.Proto.handleItemChecked = function(vItem, vChecked)
{
  if (vChecked)
  {
    this.setSelected(vItem);
  }
  else if (this.getSelected() == vItem)
  {
    this.setSelected(null);
  }
}







/*
---------------------------------------------------------------------------
  REGISTRY
---------------------------------------------------------------------------
*/

qx.Proto.add = function(varargs)
{
  var vItems = arguments;
  var vLength = vItems.length;

  var vLast = vItems[vLength-1];

  if (!(vLast instanceof qx.ui.core.Parent) && !(vLast instanceof qx.ui.basic.Terminator)) {
    vLength--;
  }

  var vItem;
  for (var i=0; i<vLength; i++)
  {
    vItem = vItems[i];

    if(qx.lang.Array.contains(this._items, vItem)) {
      return;
    }

    // Push RadioButton to array
    this._items.push(vItem);

    // Inform radio button about new manager
    vItem.setManager(this);

    // Need to update internal value?
    if(vItem.getChecked()) {
      this.setSelected(vItem);
    }

    // Make enabled the same status as the the manager has
    vItem.setEnabled(this.getEnabled());

    // Apply Make name the same
    vItem.setName(this.getName());
  }
}

qx.Proto.remove = function(vItem)
{
  // Remove RadioButton from array
  qx.lang.Array.remove(this._items, vItem);

  // Inform radio button about new manager
  vItem.setManager(null);

  // if the radio was checked, set internal selection to null
  if(vItem.getChecked()) {
    this.setSelected(null);
  }
}






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifySelected = function(propValue, propOldValue, propData)
{
  if (propOldValue && propOldValue.getChecked()) {
    propOldValue.setChecked(false);
  }

  if (propValue && !propValue.getChecked()) {
    propValue.setChecked(true);
  }

  return true;
}

qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
{
  for (var i=0, vItems=this._items, vLength=vItems.length; i<vLength; i++) {
    vItems[i].setEnabled(propValue);
  }

  return true;
}

qx.Proto._modifyName = function(propValue, propOldValue, propData)
{
  for (var i=0, vItems=this._items, vLength=vItems.length; i<vLength; i++) {
    vItems[i].setName(propValue);
  }

  return true;
}







/*
---------------------------------------------------------------------------
  SELECTION
---------------------------------------------------------------------------
*/

qx.Proto.selectNext = function(vItem)
{
  var vIndex = this._items.indexOf(vItem);

  if(vIndex == -1) {
    return;
  }

  var i = 0;
  var vLength = this._items.length;

  // Find next enabled item
  vIndex = (vIndex + 1) % vLength;
  while(i < vLength && !this._items[vIndex].getEnabled())
  {
    vIndex = (vIndex + 1) % vLength;
    i++;
  }

  this._selectByIndex(vIndex);
}

qx.Proto.selectPrevious = function(vItem)
{
  var vIndex = this._items.indexOf(vItem);

  if(vIndex == -1) {
    return;
  }

  var i = 0;
  var vLength = this._items.length;

  // Find previous enabled item
  vIndex = (vIndex - 1 + vLength) % vLength;
  while(i < vLength && !this._items[vIndex].getEnabled())
  {
    vIndex = (vIndex - 1 + vLength) % vLength;
    i++;
  }

  this._selectByIndex(vIndex);
}

qx.Proto._selectByIndex = function(vIndex)
{
  if(this._items[vIndex].getEnabled())
  {
    this.setSelected(this._items[vIndex]);
    this._items[vIndex].setFocused(true);
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

  this.forceSelected(null);

  if (this._items)
  {
    for (var i, vItems=this._items, vLength=vItems.length; i<vLength; i++)
    {
      vItems[i].dispose();
      delete vItems[i];
    }

    vItems=null;
    delete this._items;
  }

  return qx.core.Target.prototype.dispose.call(this);
}
