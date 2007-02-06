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


 ************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.AbstractButton", qx.ui.basic.Atom,
function(vText, vIcon, vIconWidth, vIconHeight, vFlash) {
  qx.ui.basic.Atom.call(this, vText, vIcon, vIconWidth, vIconHeight, vFlash);

  this.setTabIndex(1);

  // ************************************************************************
  //   MOUSE EVENTS
  // ************************************************************************
  this.addEventListener("mouseover", this._onmouseover);
  this.addEventListener("mouseout", this._onmouseout);
  this.addEventListener("mousedown", this._onmousedown);

  // ************************************************************************
  //   KEY EVENTS
  // ************************************************************************
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keypress", this._onkeypress);
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
 */

/*!
  If this tab is the currently selected/active one
 */
qx.OO.addProperty({ name : "checked", type : "boolean", defaultValue : false });

/*!
  The attached page of this tab
 */
qx.OO.addProperty({ name : "page", type : "object" });

/*!
  The assigned qx.manager.selection.RadioManager which handles the switching between registered buttons
 */
qx.OO.addProperty({ name : "manager", type : "object", instance : "qx.manager.selection.RadioManager", allowNull : true });

/*!
  The name of the radio group. All the radio elements in a group (registered by the same manager)
  have the same name (and could have a different value).
 */
qx.OO.addProperty({ name : "name", type : "string" });




/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
 */

qx.Proto.getView = function() {
  return this.getParent().getParent();
};





/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
 */

qx.Proto._modifyManager = function(propValue, propOldValue, propData) {
  if (propOldValue) {
    propOldValue.remove(this);
  }

  if (propValue) {
    propValue.add(this);
  }

  return true;
};

qx.Proto._modifyParent = function(propValue, propOldValue, propData) {
  if (propOldValue) {
    propOldValue.getManager().remove(this);
  }

  if (propValue) {
    propValue.getManager().add(this);
  }

  return qx.ui.basic.Atom.prototype._modifyParent.call(this, propValue, propOldValue, propData);
};

qx.Proto._modifyPage = function(propValue, propOldValue, propData) {
  if (propOldValue) {
    propOldValue.setButton(null);
  }

  if (propValue) {
    propValue.setButton(this);
    this.getChecked() ? propValue.show() : propValue.hide();
  }

  return true;
};

qx.Proto._modifyChecked = function(propValue, propOldValue, propData) {
  if (this._hasParent) {
    var vManager = this.getManager();
    if (vManager) {
      vManager.handleItemChecked(this, propValue);
    }
  }

  propValue ? this.addState("checked") : this.removeState("checked");

  var vPage = this.getPage();
  if (vPage) {
    this.getChecked() ? vPage.show() : vPage.hide();
  }

  return true;
};

qx.Proto._modifyName = function(propValue, propOldValue, propData) {
  if (this.getManager()) {
    this.getManager().setName(propValue);
  }

  return true;
};





/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
 */

qx.Proto._onmousedown = function(e) {
  this.setChecked(true);
};

qx.Proto._onmouseover = function(e) {
  this.addState("over");
};

qx.Proto._onmouseout = function(e) {
  this.removeState("over");
};

qx.Proto._onkeydown = function(e) {};
qx.Proto._onkeypress = function(e) {};






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


  // ************************************************************************
  //   MOUSE EVENTS
  // ************************************************************************
  this.removeEventListener("mouseover", this._onmouseover);
  this.removeEventListener("mouseout", this._onmouseout);
  this.removeEventListener("mousedown", this._onmousedown);


  // ************************************************************************
  //   KEY EVENTS
  // ************************************************************************
  this.removeEventListener("keydown", this._onkeydown);
  this.removeEventListener("keypress", this._onkeypress);


  return qx.ui.basic.Atom.prototype.dispose.call(this);
};
