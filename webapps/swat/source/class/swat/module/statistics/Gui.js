/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat statistics class graphical user interface
 */
qx.OO.defineClass("swat.module.statistics.Gui", qx.core.Object,
function()
{
  qx.core.Object.call(this);
});


/*
 * The result of our request for statistics is in this form:
 *
 *     rpc: Object
 *       status: INACTIVE
 *     smb: Object
 *       tcons: Array
 *         0: Object
 *           share_name: tmp
 *           last_use_time: 1167186771
 *           client_ip: 127.0.0.1
 *           tid: 10928
 *           connect_time: 1167186757
 *       connections: 1
 *       sessions: Array
 *         0: Object
 *           auth_time: 1167186757
 *           vuid: 24588
 *           last_use_time: 1167186771
 *           client_ip: 127.0.0.1
 *           connect_time: 1167186757
 *           account_name: Administrator
 *           domain_name: WORKGROUP
 *       status: RUNNING
 *     ldap: Object
 *       status: INACTIVE
 *     wins: Object
 *       status: DISABLED
 *     nbt: Object
 *       status: RUNNING
 *       statistics: Object
 *         total_received: 32
 *         total_sent: 4
 *         query_count: 0
 *         release_count: 0
 *         register_count: 0
 *     kdc: Object
 *       status: INACTIVE
 *     cldap: Object
 *       status: RUNNING
 */

/**
 * Build the raw graphical user interface.
 */
qx.Proto.buildGui = function(module)
{
  var o;
  var fsm = module.fsm;
  var canvas = module.canvas;

  canvas.setOverflow("auto");

  // Create a gui object where we'll put each widget handle that has varying
  // data to be displayed.
  module.gui = { };

  var addCaptionedText = function(caption, dest)
  {
    // Add a row to the destination grid
    dest.addRow();
    var row = dest.getRowCount() - 1;
    dest.setRowHeight(row, 16);

    // Add the caption
    var o = new qx.ui.basic.Label(caption);
    dest.add(o, 0, row);

    // Add the text field that will contain varying data
    o = new qx.ui.basic.Label("");
    dest.add(o, 1, row);

    // Give 'em the varying data label
    return o;
  };

  var addGroup = function(legend, top, height, width, left, right, dest)
  {
    // Add a groupbox
    var group = new qx.ui.groupbox.GroupBox(legend);
    group.setTop(top);
    if (left >= 0)
    {
      group.setLeft(left);
    }
    if (right >= 0)
    {
      group.setRight(right);
    }
    if (height >= 0)
    {
      group.setHeight(height);
    }
    if (typeof(width) == "string" || width >= 0)
    {
      group.setWidth(width);
    }
    group.setBackgroundColor("white");
    group.getLegendObject().setBackgroundColor("white");

    var grid = new qx.ui.layout.GridLayout();
    grid.setLocation(0, 0);
    grid.setDimension("100%", "100%");
    grid.setPadding(0, 0);
    grid.setRowCount(0);
    grid.setColumnCount(2);
    grid.setColumnWidth(0, 100);
    grid.setColumnWidth(1, 200);

    group.add(grid);
    dest.add(group);
    
    return grid;
  };

  // Add the RPC Service group box and its status
  var group = addGroup("RPC Service", 40, 60, "46%", 20, -1, canvas);
  module.gui.rpc =
  {
    status : addCaptionedText("Status:", group)
  };

  // Add the KDC Service group box and its status
  var group = addGroup("KDC Service", 40, 60, "46%", -1, 20, canvas);
  module.gui.kdc =
  {
    status : addCaptionedText("Status:", group)
  };

  // Add the LDAP Service group box and its status
  var group = addGroup("LDAP Service", 120, 60, "46%", 20, -1, canvas);
  module.gui.ldap =
  {
    status : addCaptionedText("Status:", group)
  };

  // Add the CLDAP Service group box and its status
  var group = addGroup("CLDAP Service", 120, 60, "46%", -1, 20, canvas);
  module.gui.cldap =
  {
    status : addCaptionedText("Status:", group)
  };

  // Add the WINS Service group box and its status
  var group = addGroup("WINS Service", 200, 60, "46%", 20, -1, canvas);
  module.gui.wins =
  {
    status : addCaptionedText("Status:", group)
  };

  // Add the NBT Service group box and its status, and the statistics
  var group = addGroup("NBT Service", 200, 140, "46%", -1, 20, canvas);
  module.gui.nbt = 
  {
    status         : addCaptionedText("Status:", group),
    total_received : addCaptionedText("Total received:", group),
    total_sent     : addCaptionedText("Total sent:", group),
    query_count    : addCaptionedText("Query count:", group),
    release_count  : addCaptionedText("Release count:", group),
    register_count : addCaptionedText("Register count:", group)
  };

  // Add the SMB Service group box (sans grid) and its status
  var group = new qx.ui.groupbox.GroupBox("SMB Service");
  group.set({
                top:    360,
                height: 400,
                left:   20,
                right:  20
            });
  group.setBackgroundColor("white");
  group.getLegendObject().setBackgroundColor("white");

  // Create the Status block
  o = new qx.ui.basic.Label("Status:");
  o.set({
            top    : 0,
            left   : 0,
            width  : 100
        });
  group.add(o);

  o = new qx.ui.basic.Label("");
  o.set({
            top    : 0,
            left   : 100,
            width  : 200
        });
  group.add(o);

  // Add the status and create the table models for sessions and connections
  module.gui.smb =
  {
    status   : o,
    sessions : new qx.ui.table.SimpleTableModel(),
    tcons    : new qx.ui.table.SimpleTableModel()
  };

  // Begin the Sessions section
  o = new qx.ui.basic.Label("Sessions");
  o.set({
            top    : 20,
            left   : 20
        });
  group.add(o);

  // Set column labels
  var tableModel = module.gui.smb.sessions;
  tableModel.setColumns([
                          "User",
                          "Client",
                          "Connected at",
                          "Authenticated at",
                          "Last used at",
                          "VUID"
                        ]);
  tableModel.setData([ ]);

  // Create the table for sessions
  var table = new qx.ui.table.Table(tableModel);
  table.set({
                top    : 40,
                left   : 20,
                right  : 20,
                height : 160
            });
  table.setMetaColumnCounts([1, -1]);
  table.setStatusBarVisible(false);
  table.setColumnVisibilityButtonVisible(false);
  table.setColumnWidth(0, 260);
  table.setColumnWidth(1, 80);
  table.setColumnWidth(2, 120);
  table.setColumnWidth(3, 120);
  table.setColumnWidth(4, 120);
  table.setColumnWidth(5, 60);

  // Add the table to the groupbox
  group.add(table);
  canvas.add(group);

  // Begin the Connections section
  o = new qx.ui.basic.Label("Connections");
  o.set({
            top    : 220,
            left   : 20
        });
  group.add(o);

  // Create the table model for tcons
  var tableModel = module.gui.smb.tcons;
  tableModel.setColumns([
                          "Share",
                          "Client",
                          "Connected at",
                          "Last used at",
                          "TID"
                        ]);
  tableModel.setData([ ]);

  // Create the table for sessions
  var table = new qx.ui.table.Table(tableModel);
  table.set({
                top    : 240,
                left   : 20,
                right  : 20,
                bottom : 20
            });
  table.setMetaColumnCounts([1, -1]);
  table.setStatusBarVisible(false);
  table.setColumnVisibilityButtonVisible(false);
  table.setColumnWidth(0, 260);
  table.setColumnWidth(1, 80);
  table.setColumnWidth(2, 120);
  table.setColumnWidth(3, 120);
  table.setColumnWidth(4, 60);

  // Add the table to the groupbox
  group.add(table);
  canvas.add(group);

};


/**
 * Populate the graphical user interface with the specified data
 *
 * @param module {swat.main.Module}
 *   The module descriptor for the module.
 *
 * @result {Object}
 *   The result returned by SAMBA to our request for statistics.  We display
 *   the data provided by this result.
 */
qx.Proto.displayData = function(module, result)
{
  var gui = module.gui;

  if (result.type == "failed")
  {
    // Have we already put up the FAILED message?
    if (gui.failed)
    {
      // Yup.
      gui.failed.setDisplay(true);
      return;
    }

    // Create a semi-transparent layover o which to display a failure message
    gui.failed = new qx.ui.layout.CanvasLayout();
    gui.failed.set({
                   top: 0,
                   bottom: 0,
                   left: 0,
                   right: 0
               });
    gui.failed.setBackgroundColor("white");
    gui.failed.setDisplay(true); // initially displayed
    gui.failed.setOpacity(0.7);  // semi-transparent

    // Add the failure message
    var style =
      "color: red;" +
      "font-size: large;" +
      "font-weight: bold;";
    var o = new qx.ui.basic.Label("<span style='" + style + "'>" +
                                  "Communication with SAMBA failed!",
                                  "</span>");
    o.set({
              top    : 0,
              left   : 20
          });
    gui.failed.add(o);

    // Add the failed layover to the canvas
    module.canvas.add(gui.failed);

    return;
  }

  // Successful RPC request.
  // If the failure message was displayed, we no longer need it.
  if (gui.failed)
  {
    gui.failed.setDisplay(false);
  }

  // Create a function for formatting dates
  var dateFormat = function(unixepoch)
  {
    if (unixepoch == 0)
    {
      return "";
    }

    var d = new Date(unixepoch * 1000);
    return (d.getFullYear() + "-" +
            ("0" + (d.getMonth() + 1)).substr(-2) + "-" +
            ("0" + d.getDate()).substr(-2) + " " +
            ("0" + d.getHours()).substr(-2) + ":" +
            ("0" + d.getMinutes()).substr(-2));
  }

  // Set the status values
  gui.rpc.status.setHtml(result.data.rpc.status);
  gui.kdc.status.setHtml(result.data.kdc.status);
  gui.ldap.status.setHtml(result.data.ldap.status);
  gui.cldap.status.setHtml(result.data.cldap.status);
  gui.wins.status.setHtml(result.data.wins.status);
  gui.nbt.status.setHtml(result.data.nbt.status);
  gui.smb.status.setHtml(result.data.smb.status);

  // If the NBT service is running...
  if (result.data.nbt.status == "RUNNING")
  {
    // ... then output the statistics
    gui.nbt.total_received.setHtml(
      result.data.nbt.statistics.total_received.toString());
    gui.nbt.total_sent.setHtml(
      result.data.nbt.statistics.total_sent.toString());
    gui.nbt.query_count.setHtml(
      result.data.nbt.statistics.query_count.toString());
    gui.nbt.release_count.setHtml(
      result.data.nbt.statistics.release_count.toString());
    gui.nbt.register_count.setHtml(
      result.data.nbt.statistics.register_count.toString());
  }
  else
  {
    // otherwise, clear the statistics fields
    gui.nbt.total_received.setHtml("");
    gui.nbt.total_sent.setHtml("");
    gui.nbt.query_count.setHtml("");
    gui.nbt.release_count.setHtml("");
    gui.nbt.register_count.setHtml("");
  }

  // Initialize data for sessions list
  var rowData = [];

  // If there are any sessions...
  if (result.data.smb.sessions instanceof Array)
  {
    // ... then for each session...
    for (var i = 0; i < result.data.smb.sessions.length; i++)
    {
      // ... add its info to the table data
      var sess = result.data.smb.sessions[i];
      rowData.push([
                     sess.account_name + "/" + sess.domain_name,
                     sess.client_ip,
                     dateFormat(sess.connect_time),
                     dateFormat(sess.auth_time),
                     dateFormat(sess.last_use_time),
                     sess.vuid.toString()
                   ]);
    }
  }

  // Whether there were sessions or not, reset the session table data
  gui.smb.sessions.setData(rowData);

  // Initialize data for tcons list
  var rowData = [];

  // If there are any tcons...
  if (result.data.smb.tcons instanceof Array)
  {
    // ... then for each tcon...
    for (var i = 0; i < result.data.smb.tcons.length; i++)
    {
      // ... add its info to the table data
      var conn = result.data.smb.tcons[i];
      rowData.push([
                     conn.share_name,
                     conn.client_ip,
                     dateFormat(conn.connect_time),
                     dateFormat(conn.last_use_time),
                     conn.tid.toString()
                   ]);
    }
  }

  // Whether there were tcons or not, reset the tcon table data
  gui.smb.tcons.setData(rowData);
};

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
