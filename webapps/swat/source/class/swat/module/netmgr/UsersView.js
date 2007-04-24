/*
 * Copyright (C)  Rafal Szczesniak 2007
 */

//qx.OO.addProperty({ name: "_fsm", type: "object"});
//qx.OO.addProperty({ name: "_columns", type: "object"});
//qx.OO.addProperty({ name: "_items", type: "object"});
//qx.OO.addProperty({ name: "_view", type: "object" });

/**
 * Users View 
 */
qx.OO.defineClass("swat.module.netmgr.UsersView", qx.ui.layout.HorizontalBoxLayout,
function(fsm, domainName)
{
  qx.ui.layout.HorizontalBoxLayout.call(this);

  this._fsm = fsm;
  
  // Set the whole view panel size and spacing between boxes
  this.set({ top: 0, left: 0, width: "100%", height: "100%" });
  this.setSpacing(5);

  // Provide vertical positioning of combo box and list view
  var innerBox = new qx.ui.layout.VerticalBoxLayout();
  innerBox.set({ top: 0, left: 0, width: "100%", height: "100%"});

  // horizontal box for domain selection label and combo box
  var selectDomainBox = new qx.ui.layout.HorizontalBoxLayout();
  selectDomainBox.set({ top: 0, left: 0, width: "auto", height: "10%" });
  selectDomainBox.setVerticalChildrenAlign("middle");
  selectDomainBox.setSpacing(5);
  
  // Setup domain selection combo box
  var lblDomain = new qx.ui.basic.Atom("Domain:");
  lblDomain.setHorizontalChildrenAlign("right");
  
  var cmbDomain = new qx.ui.form.ComboBox();
  cmbDomain.setEditable(false);

  // there's always BUILTIN domain so add it to the list
  var item = new qx.ui.form.ListItem("BUILTIN");
  cmbDomain.add(item);

  var selectedItem = undefined;
  
  // Simply add the domain name if it is passed as a string
  if (typeof(domainName) == "string")
  {
    item = new qx.ui.form.ListItem(domainName);
    cmbDomain.add(item);

    selectedItem = item;
  }
  else // if it's not a string we assume it is a list of strings
  {
    for (var s in domainName)
    {
      item = new qx.ui.form.ListItem(s);
      cmbDomain.add(s);
    }

    selectedItem = new qx.ui.form.ListItem(domainName[0]);
  }

  // Add event handling
  cmbDomain.addEventListener("changeSelected", fsm.eventListener, fsm);
  fsm.addObject("domainName", cmbDomain);

  // Set default selection and dispatch the respective event to initialise the view
  cmbDomain.setSelected(selectedItem);

  // Create an empty list view with sample column
  this._columns = { username : { label: "Username", width: 150, type: "text" }};
  this._items = [];
  this._view = new qx.ui.listview.ListView(this._items, this._columns);
  var view = this._view;
  view.set({ top: 0, left: 0, width: "90%", height: "90%" });
  view.setBorder(qx.renderer.border.BorderPresets.getInstance().shadow);

  // Arrange widgets and boxes
  selectDomainBox.add(lblDomain);
  selectDomainBox.add(cmbDomain);

  innerBox.add(selectDomainBox);
  innerBox.add(view);

  // place the inner box in the UsersView box
  this.add(innerBox);
});


// UsrMgr context is required for any operation on user accounts
qx.OO.addProperty({ name : "usrCtx", type : "number" });


qx.Proto.refreshView = function()
{
}


qx.Proto._initUserManager = function(module, rpcRequest)
{
  // Get obtained UsrCtx handle
  var usrCtx = rpcRequest.getUserData("result").data;
};
