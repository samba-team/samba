/*                                                                                                                    
 * Copyright::                                                                                                         
 *   (C) 2006 by Simo Sorce
 * 
 * License: 
 *   GPL v2 or later
 */

/**
 * Ldb Modifier Class
 */

qx.OO.defineClass("swat.module.ldbbrowse.LdbModify", qx.ui.layout.VerticalBoxLayout,
function(fsm)
{
  qx.ui.layout.VerticalBoxLayout.call(this);

  this._mainArea = new qx.ui.layout.VerticalBoxLayout();
  this._mainArea.set({
                     overflow: "auto",
                     height: "1*",
                     spacing: 5
                    });

  // Add an horizonatl layout for the "New" and "Modify" buttons
  // We need a vertical box layout for the tree and the buttons
  this._hlayout = new qx.ui.layout.HorizontalBoxLayout();
  this._hlayout.set({
               height: "auto",
               spacing: 10
           });

  // add a spacer to align buttons to the right
  this._leftSpacer = new qx.ui.basic.HorizontalSpacer();

  // Add the "Cancel" button
  this._cancelbtn = new qx.ui.form.Button("Cancel");
  this._cancelbtn.addEventListener("execute", this._cancelOp, this);

  // Add the "OK" button
  this._okbtn = new qx.ui.form.Button("OK");
  this._okbtn.addEventListener("execute", fsm.eventListener, fsm);

  // We'll be receiving events on the object, so save its friendly name
  fsm.addObject("commit", this._okbtn, "swat.main.fsmUtils.disable_during_rpc");

  // Add the buttons to the hlayout
  this._hlayout.add(this._leftSpacer, this._cancelbtn, this._okbtn);
  
  // Add the hlayout to the vlayout.
  this.add(this._mainArea, this._hlayout);

  // By default this is a new record creator
  this._type = "add";

  // By default this is inactive
  this._active = false;

  this.basedn = "";

  this._amw = null;
});

qx.OO.addProperty({ name : "basedn", type : "string" });

/**
 * Set the type of operation
 * 
 * @param type {String}
 *   A string containing "new" or "modify"
 *
 * @param data {Object}
 *   An LDB object with the current object parameters
 *   Used only if type = "modify"
 *
 */

qx.Proto.isActive = function() {
  if (this._active == true) {
    return true;
  }
}

/** 
 * Set the base of the object to add
 *
 * @param type {String}
 *   A string containing the base DN
 */

qx.Proto.setBase = function(base) {

  this.basedn = base;

  if (this._active) {
    if (this._type == "add") {

      this._basedn.setValue(this.basedn);
      this._basedn.setWidth(8 * this.basedn.length);
    }
  }
}

qx.Proto.initNew = function(callback, obj) {

  this._setExitCallback(callback, obj);

  this._active = true;
  this._type = "add";

  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.set({ height: "auto", spacing: 10 });

  var dnlabel = new qx.ui.basic.Label("DN: ");

  // The name of the new/modified object
  // TODO: add validator
  this._rdn = new qx.ui.form.TextField(""); 
  this._rdn.setWidth(128);

  var dnsep = new qx.ui.basic.Label(",");

  // The basedn of the object
  // TODO: add validator
  this._basedn = new qx.ui.form.TextField(this.basedn);
  this._basedn.setWidth(8 * this.basedn.length);

  hlayout.add(dnlabel, this._rdn, dnsep, this._basedn);

  this._mainArea.add(hlayout);

  this._createAttributesArea();

  return;
}

qx.Proto.initMod = function(tablemodel, callback, obj) {

  this._setExitCallback(callback, obj);

  if (this.basedn == "") {
    this._callExitCallback();
    return;
  }

  this._active = true;
  this._type = "modify";

  this._dn = new qx.ui.basic.Label("DN: " + this.basedn);

  this._mainArea.add(this._dn);

  this._createAttributesArea();

  // for each entry in the table, add new entries in the object
  var count = tablemodel.getRowCount();
  for (var i = 0; i < count; i++) {
    var row = tablemodel.getRowData(i);
    this._addNewAttribute(row[0], row[1]);
  }

  this._modBaseTableModel = tablemodel;
}

qx.Proto._setExitCallback = function(vFunction, vObject) {

  if(typeof vFunction !== "function") {
    throw new Error("swat.module.ldbbrowse.LdbModify: setExitCallback(" + vFunction + "' is not a function!");
  }

  this._exitCallback = {
      handler : vFunction,
      object : vObject
    }
}

qx.Proto._callExitCallback = function() {

  // Shortcuts for handler and object
  vFunction = this._exitCallback.handler;
  vObject = this._exitCallback.object;

  // Call object function
  try
  {
    if(typeof vFunction === "function") {
      vFunction.call(qx.util.Validation.isValid(vObject) ? vObject : this);
    }
  }
  catch(ex)
  {
    this.error("swat.module.ldbbrowse.LdbModify: Could not call exit callback: ", ex);
  }
}

qx.Proto._reset = function() {

  // Remove existing attributes
  this._mainArea.removeAll();
  this._active = false;
  this._type = "null";
  return;
}

qx.Proto._cancelOp = function() {

  this._reset();
  this._callExitCallback();
}

qx.Proto._okOp = function() {

  //TODO: disable ok/cancel buttons and call fsm instead
  this._reset();
  this._callExitCallback();
}

qx.Proto._addNewAttribute = function(name, value, before) {

  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.set({ width: "auto", height: "auto", spacing: 10 });

  var aButton = new qx.ui.form.Button("+");
  aButton.set({ width: 15, height: 15});
  aButton.addEventListener("execute", function() {
    this._addNewAttribute(name, null, hlayout);
  }, this);

  var aNameTextField = new qx.ui.form.TextField(name);
  aNameTextField.setWidth(150);

  var aValTextField = new qx.ui.form.TextField(value);
  aValTextField.setWidth(250);

  var rButton = new qx.ui.form.Button("-");
  rButton.set({ left: 5, width: 15, height: 15});
  rButton.addEventListener("execute", function() {
    hlayout.setParent(null);
  }, this);

  hlayout.add(aButton, aNameTextField, aValTextField, rButton);
  hlayout.setUserData("attrName", aNameTextField);
  hlayout.setUserData("attrVal", aValTextField);

  if (before) {
    this._attrArea.addAfter(hlayout, before);
  } else {
    //TODO: check the same attribute is not already present, if so just add a new value instead
    this._attrArea.addBefore(hlayout, this._attrAddButton);
  }
}

qx.Proto._createAttributesArea = function() {

  this._attrArea = new qx.ui.layout.VerticalBoxLayout();

  this._attrAddButton = new qx.ui.form.Button("+");
  this._attrAddButton.set({ width: 15, height: 15});
  this._attrAddButton.addEventListener("execute", this._addNewAttribute, this);

  this._attrArea.add(this._attrAddButton);

  this._mainArea.add(this._attrArea);
}

qx.Proto.getOpType = function() {
  return this._type;
}

qx.Proto.getLdif = function() {
  //TODO: modify
  if (this._type != "add") {
    return null;
  }

  var ldif = "# Add operation\n";
  ldif = ldif + "dn: " + this._rdn.getValue() + "," + this._basedn.getValue() + "\n";

  c = this._attrArea.getChildren();

  for (var i = 0; i < c.length; i++) {
    if (c[i] instanceof qx.ui.layout.HorizontalBoxLayout) {
      ldif = ldif + c[i].getUserData("attrName").getComputedValue() + ": " + c[i].getUserData("attrVal").getComputedValue() + "\n";
    }
  }
  // terminate ldif record
  ldif = ldif + "\n";

  return ldif;
}
