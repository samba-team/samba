/*
 * Copyright:
 *   (C) 2007 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat authentication window class
 */
qx.OO.defineClass("swat.main.Authenticate", qx.ui.window.Window,
function()
{
  var o;

  qx.ui.window.Window.call(this);

  var addCaptionedWidget = function(caption, dest, addWidget)
  {
    // Add a row to the destination grid
    dest.addRow();
    var row = dest.getRowCount() - 1;
    dest.setRowHeight(row, 24);

    // Add the caption
    var o = new qx.ui.basic.Label(caption);
    dest.add(o, 0, row);

    // Add the widget
    o = addWidget();
    o.setHeight(24);
    dest.add(o, 1, row);

    // Give 'em the varying data label
    return o;
  };


  // Set characteristics of this window
  this.set({
             width         : 380,
             height        : 200,
             modal         : true,
             centered      : true,
             showClose     : false,
             showMaximize  : false,
             showMinimize  : false,
             showStatusbar : false,
             allowClose    : false,
             allowMaximize : false,
             allowMinimize : false,
             resizeable    : false,
             moveable      : false,
             zIndex        : 10000
           });


  // Create a grid layout
  var grid = new qx.ui.layout.GridLayout();
  grid.setLocation(14, 14);
  grid.setDimension("90%", "90%");
  grid.setVerticalSpacing(14);
  grid.setPadding(14, 14);
  grid.setRowCount(0);
  grid.setColumnCount(2);
  grid.setColumnWidth(0, 100);
  grid.setColumnWidth(1, 200);


  // Add an input box for the user name
  this.userName = addCaptionedWidget("User Name", grid,
                                     function()
                                     {
                                       return new qx.ui.form.TextField();
                                     });

  // Add an input box for the password
  this.password = addCaptionedWidget("Password", grid,
                                     function()
                                     {
                                       return new qx.ui.form.PasswordField();
                                     });

  // Add an input box for the password
  this.domain = addCaptionedWidget("Domain", grid,
                                   function()
                                   {
                                     // Create a combo box for for the domain
                                     var combo = new qx.ui.form.ComboBox();
                                     combo.setEditable(false);
                                     return combo;
                                   });

  // Add a login button
  this.login = addCaptionedWidget("", grid,
                                  function()
                                  {
                                    return new qx.ui.form.Button("Login");
                                  });

  // Add the grid to the window
  this.add(grid);

  // Add this window to the document
  this.addToDocument();
});


qx.Proto.addToFsm = function(fsm)
{
  // Have we already been here for this fsm?
  if (fsm.getObject("login_window"))
  {
    // Yup.  Everything's already done.  See ya!
    return;
  }

  // Save the login button since we receive events on it
  fsm.addObject("login_button", this.login);

  // We want to receive "execute" events on this button
  this.login.addEventListener("execute", fsm.eventListener, fsm);

  // Save the window object
  fsm.addObject("login_window", this);

  // We want to receive "complete" events on this window (which we generate)
  this.addEventListener("complete", fsm.eventListener, fsm);
};


qx.Proto.setInfo = function(info)
{
  this.debug(info);

  // Remove everythingn from the domain list
  this.domain.removeAll();

  // Add the available domains
  for (var i = 0; i < info.length; i++)
  {
    var item = new qx.ui.form.ListItem(info[i]);
    this.domain.add(item);
  }
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
