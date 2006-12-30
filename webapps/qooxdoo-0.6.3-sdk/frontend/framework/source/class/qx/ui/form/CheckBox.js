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

qx.OO.defineClass("qx.ui.form.CheckBox", qx.ui.basic.Atom,
function(vText, vValue, vName, vChecked)
{
  qx.ui.basic.Atom.call(this, vText);

  this.setTabIndex(1);
  this.setPadding(2, 3);

  this._createIcon();

  if (qx.util.Validation.isValidString(vValue)) {
    this.setValue(vValue);
  }

  if (qx.util.Validation.isValidString(vName)) {
    this.setName(vName);
  }

  if (qx.util.Validation.isValidBoolean(vChecked)) {
    this.setChecked(vChecked);
  } else {
    this.setChecked(false);
  }

  this.addEventListener("click", this._onclick);
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keyup", this._onkeyup);
});

/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.OO.removeProperty({ name : "icon" });
qx.OO.removeProperty({ name : "disabledIcon" });

/*!
  The HTML name of the form element used by the widget
*/
qx.OO.addProperty({ name : "name", type : "string" });

/*!
  The HTML value of the form element used by the widget
*/
qx.OO.addProperty({ name : "value", type : "string" });

/*!
  If the widget is checked
*/
qx.OO.addProperty({ name : "checked", type : "boolean", getAlias : "isChecked" });





/*
---------------------------------------------------------------------------
  ICON HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.INPUT_TYPE = "checkbox";

qx.Proto._createIcon = function()
{
  var i = this._iconObject = new qx.ui.form.InputCheckSymbol;

  i.setType(this.INPUT_TYPE);
  i.setChecked(this.isChecked());
  i.setEnabled(this.isEnabled());
  i.setAnonymous(true);

  this.addAtBegin(i);
}





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

  return true;
}

qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
{
  if (this._iconObject) {
    this._iconObject.setEnabled(propValue);
  }

  return qx.ui.basic.Atom.prototype._modifyEnabled.call(this, propValue, propOldValue, propData);
}




/*
---------------------------------------------------------------------------
  HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._handleIcon = function()
{
  switch(this.getShow())
  {
    case qx.ui.basic.Atom.SHOW_ICON:
    case qx.ui.basic.Atom.SHOW_BOTH:
      this._iconIsVisible = true;
      break;

    default:
      this._iconIsVisible = false;
  }

  if (this._iconIsVisible)
  {
    this._iconObject ? this._iconObject.setDisplay(true) : this._createIcon();
  }
  else if (this._iconObject)
  {
    this._iconObject.setDisplay(false);
  }
}




/*
---------------------------------------------------------------------------
  EVENT-HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onclick = function(e) {
  this.toggleChecked();
};


qx.Proto._onkeydown = function(e)
{
  if(e.getKeyIdentifier() == "Enter" && !e.getAltKey()) {
    this.toggleChecked();
  }
};


qx.Proto._onkeyup = function(e)
{
  if(e.getKeyIdentifier() == "Space") {
    this.toggleChecked();
  }
};



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

  this.removeEventListener("click", this._onclick);
  this.removeEventListener("keydown", this._onkeydown);
  this.removeEventListener("keyup", this._onkeyup);

  return qx.ui.basic.Atom.prototype.dispose.call(this);
}
