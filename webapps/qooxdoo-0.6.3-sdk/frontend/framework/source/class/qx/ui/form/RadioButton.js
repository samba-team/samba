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

qx.OO.defineClass("qx.ui.form.RadioButton", qx.ui.form.CheckBox,
function(vText, vValue, vName, vChecked) {
  qx.ui.form.CheckBox.call(this, vText, vValue, vName, vChecked);

  this.addEventListener("keypress", this._onkeypress);
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The assigned qx.manager.selection.RadioManager which handles the switching between registered buttons
*/
qx.OO.addProperty({ name : "manager", type : "object", instance : "qx.manager.selection.RadioManager", allowNull : true });





/*
---------------------------------------------------------------------------
  ICON HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.INPUT_TYPE = "radio";




/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyChecked = function(propValue, propOldValue, propData)
{
  if (this._iconObject) {
    this._iconObject.setChecked(propValue);
  }

  var vManager = this.getManager();
  if (vManager) {
    vManager.handleItemChecked(this, propValue);
  }

  return true;
}

qx.Proto._modifyManager = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    propOldValue.remove(this);
  }

  if (propValue) {
    propValue.add(this);
  }

  return true;
}

qx.Proto._modifyName = function(propValue, propOldValue, propData)
{
  if (this._iconObject) {
    this._iconObject.setName(propValue);
  }

  if (this.getManager()) {
    this.getManager().setName(propValue);
  }

  return true;
}

qx.Proto._modifyValue = function(propValue, propOldValue, propData)
{
  if (this.isCreated() && this._iconObject) {
    this._iconObject.setValue(propValue);
  }

  return true;
}






/*
---------------------------------------------------------------------------
  EVENT-HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onkeydown = function(e)
{
  if (e.getKeyIdentifier() == "Enter" && !e.getAltKey()) {
    this.setChecked(true);
  }
};


qx.Proto._onkeypress = function(e)
{
 switch(e.getKeyIdentifier())
  {
    case "Left":
    case "Up":
      qx.event.handler.FocusHandler.mouseFocus = false;
      // we want to have a focus border when using arrows to select
      qx.event.handler.FocusHandler.mouseFocus = false;

      return this.getManager() ? this.getManager().selectPrevious(this) : true;

    case "Right":
    case "Down":
      // we want to have a focus border when using arrows to select
      qx.event.handler.FocusHandler.mouseFocus = false;

      return this.getManager() ? this.getManager().selectNext(this) : true;
  }
};


qx.Proto._onclick = function(e) {
  this.setChecked(true);
}

qx.Proto._onkeyup = function(e)
{
  if(e.getKeyIdentifier() == "Space") {
    this.setChecked(true);
  }
}





/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if(this.getDisposed()) {
    return;
  }

  this.removeEventListener("keypress", this._onkeypress);
  return qx.ui.form.CheckBox.prototype.dispose.call(this);
}
