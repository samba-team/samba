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

  this._fsm = fsm;

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
  this._okbtn.addEventListener("execute", this._fsm.eventListener, this._fsm);

  // We'll be receiving events on the object, so save its friendly name
  this._fsm.addObject("commit", this._okbtn, "swat.main.fsmUtils.disable_during_rpc");

  // Add the buttons to the hlayout
  this._hlayout.add(this._leftSpacer, this._cancelbtn, this._okbtn);
  
  // Add the hlayout to the vlayout.
  this.add(this._mainArea, this._hlayout);

  // By default this is a new record creator
  this._type = "add";

  // By default this is inactive
  this._active = false;

  this.basedn = "";

  this._dmw = null;
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

qx.Proto.getBase = function() {

  return this.basedn;

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

  this._modBaseHash = new Array();

  // for each entry in the table, add new entries in the object
  var count = tablemodel.getRowCount();
  for (var i = 0; i < count; i++) {
    var row = tablemodel.getRowData(i);
    this._addNewAttribute(row[0], row[1]);
    if (this._modBaseHash[row[0]] == null) {
      this._modBaseHash[row[0]] = new Array();
    }
    this._modBaseHash[row[0]].push(row[1]);
  }
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

  if (this._active != true) {
    return null;
  }

  c = this._attrArea.getChildren();

  switch (this._type) {

  case "add":

    var ldif = "dn: " + this._rdn.getValue() + "," + this._basedn.getValue() + "\n";

    for (var i = 0; i < c.length; i++) {
      if (c[i] instanceof qx.ui.layout.HorizontalBoxLayout) {
        ldif = ldif + c[i].getUserData("attrName").getComputedValue() + ": " + c[i].getUserData("attrVal").getComputedValue() + "\n";
      }
    }
    break;

  case "modify":

    var ldif = "dn: " + this.basedn + "\n";

    ldif = ldif + "changetype: modify\n";

    var submAttrs = new Array();

    // Build an array of the submitted data
    for (var i = 0; i < c.length; i++) {
      if (c[i] instanceof qx.ui.layout.HorizontalBoxLayout) {

        var attrName = c[i].getUserData("attrName").getComputedValue();
        var attrVal = c[i].getUserData("attrVal").getComputedValue();
        
        if (submAttrs[attrName] == null) {
          submAttrs[attrName] = new Array();
        }
        submAttrs[attrName].push(attrVal);
      }
    }

    // compare arrays and find out what changed, built an hash of the modifications
    var modAttrs = new Array();

    for (var i in this._modBaseHash) {
      modAttrs[i] = new Array();
      modAttrs[i][0] = "skip";

      if (submAttrs[i] == null) {
        modAttrs[i][0] = "delete";
      } else {
        // check if the arrays are identical
        if (this._modBaseHash[i].length <= submAttrs[i].length) {
          for (var j = 0; j < this._modBaseHash[i].length; j++) {
            for (var k = 0; k < submAttrs[i].length; k++) {
              if (this._modBaseHash[i][j] == submAttrs[i][k]) {
                break;
              }
            }
            if (k >= submAttrs[i].length) {
              modAttrs[i][0] = "replace";
              break;
            }
          }
          // if all the attributes in base hash are contained in sumbAttr
          // it means only additions were done, sort out what was addedd
          if (modAttrs[i][0] != "replace") {
            for (var j = 0; j < submAttrs[i].length; j++) {
              for (var k = 0; k < this._modBaseHash[i].length; k++) {
                if (submAttrs[i][j] == this._modBaseHash[i][k]) break;
              }
              // this element was not found in original array
              if (k >= this._modBaseHash[i].length) {
                if (modAttrs[i][0] != "add") {
                  modAttrs[i][0] = "add";
                }
                modAttrs[i].push(submAttrs[i][j]);
              }
            }
          }
        } else {
          modAttrs[i] = [ "replace" ];
        }
      }
      // if they differ replace the whole content
      if (modAttrs[i][0] == "replace") {
        for (var j = 0; j < submAttrs[i].length; j++) {
          modAttrs[i].push(submAttrs[i][j]);
        }
      }

      // wipe out attr from sumbAttr, so that we can later found truly new attrs addedd to the array
      submAttrs[i] = null;
    }

    for (var i in submAttrs) {
      if (submAttrs[i] != null) {
        modAttrs[i] = new Array();
        modAttrs[i][0] = "add";

        for (var j = 0; j < submAttrs[i].length; j++) {
          modAttrs[i].push(submAttrs[i][j]);
        }
      }
    }

    //track if we did any mod at all
    var nmods = 0;

    for (var i in modAttrs) {
      switch (modAttrs[i][0]) {

      case "delete":
        nmods++;
        ldif = ldif + "delete: " + i + "\n";
        break;

      case "add":
        nmods++;
        ldif = ldif + "add: " + i + "\n";
        for (var j = 1; j < modAttrs[i].length; j++) {
          ldif = ldif + i + ": " + modAttrs[i][j] + "\n";
        }
        break;

      case "replace":
        nmods++;
        ldif = ldif + "replace: " + i + "\n";
        for (var j = 1; j < modAttrs[i].length; j++) {
          ldif = ldif + i + ": " + modAttrs[i][j] + "\n";
        }
        break;

      default:
        //skip
        break;
      }
    }

    if (nmods == 0) {
      alert("No modifications?");
    }

    break;

  default:

    return null;

  }

  // terminate ldif record
  ldif = ldif + "\n";

  return ldif;
};

qx.Proto.showConfirmDelete = function() {

  var main = qx.ui.core.ClientDocument.getInstance();

  if (this._dmw == null) {
    this._dmw = new qx.ui.window.Window("-- DELETE Object --");
    this._dmw.set({
      width: 300,
      height: 125,
      modal: true,
      centered: true,
      restrictToPageOnOpen: true,
      showMinimize: false,
      showMaximize: false,
      showClose: false,
      resizeable: false
    });

    var warningLabel = new qx.ui.basic.Label("Error Dialog not initialized!");
    this._dmw.add(warningLabel);
    this._dmw.setUserData("label", warningLabel);

    var cancelButton = new qx.ui.form.Button("Cancel");
    cancelButton.addEventListener("execute", function() {
      this._dmw.close();
    }, this);
    cancelButton.set({ top: 45, left: 32 }); 
    this._dmw.add(cancelButton);

    this._dmw.addEventListener("appear",function() { 
      cancelButton.focus();
    }, this._dmw);

    main.add(this._dmw);
    var okButton = new qx.ui.form.Button("OK");
    okButton.addEventListener("execute", function() {
      this._dmw.close();
    }, this);
    // We'll be receiving events on the object, so save its friendly name
    this._fsm.addObject("delete", okButton, "swat.main.fsmUtils.disable_during_rpc");
    okButton.addEventListener("execute", this._fsm.eventListener, this._fsm);
      
    okButton.set({ top: 45, right: 32 });
    this._dmw.add(okButton);

    main.add(this._dmw);
  }

  var label = this._dmw.getUserData("label");

  label.setHtml("<pre>Do you really want to delete\n" + this.basedn + " ?</pre>");

  this._dmw.open();
};
