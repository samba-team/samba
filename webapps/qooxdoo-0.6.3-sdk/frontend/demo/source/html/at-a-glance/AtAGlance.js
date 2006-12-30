/* ************************************************************************

   qooxdoo - the new era of web development

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany
     http://www.1und1.de | http://www.1and1.com
     All rights reserved

   License:
     LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/

   Internet:
     * http://qooxdoo.org

   Authors:
     * Sebastian Werner (wpbasti)
       <sebastian dot werner at 1und1 dot de>
     * Andreas Ecker (ecker)
       <andreas dot ecker at 1und1 dot de>
     * Til Schneider (til132)
       <tilman dot schneider at stz-ida dot de>

************************************************************************ */

qx.OO.defineClass("AtAGlance", qx.core.Object,
function () {
  qx.core.Object.call(this);

  var barView = new qx.ui.pageview.buttonview.ButtonView;

  barView.setLocation(10, 10);
  barView.setRight(10);
  barView.setBottom(10);

  barView.addToDocument();

  this._createPage(barView, "Form",             "icon/32/wordprocessor.png",    this._createFormDemo(), "threedface");
  this._createPage(barView, "Tooltip",          "icon/32/run.png",              this._createTooltipDemo());
  this._createPage(barView, "Menu and Toolbar", "icon/32/display.png",          this._createToolbarDemo());
  this._createPage(barView, "Tab",              "icon/32/contents.png",         this._createTabDemo(), "threedface", true);
  this._createPage(barView, "Tree",             "icon/32/view-sidetree.png",    this._createTreeDemo(), "threedface");
  this._createPage(barView, "List",             "icon/32/view-detailed.png",    this._createListDemo(), "threedface");
  this._createPage(barView, "ListView",         "icon/32/view-multicolumn.png", this._createListViewDemo(), "threedface");
  this._createPage(barView, "Table",            "icon/32/view-multicolumn.png", this._createTableDemo(), "threedface", true);
  this._createPage(barView, "DateChooser",      "icon/32/date.png",             this._createDateChooserDemo(), "threedface");
  this._createPage(barView, "Native Window",    "icon/32/display.png",          this._createNativeWindowDemo(), "threedface");
  this._createPage(barView, "Internal Window",  "icon/32/look-and-feel.png",    this._createInternalWindowDemo(), null, true);
  this._createPage(barView, "Themes",           "icon/32/style.png",            this._createThemesDemo());
});


qx.Proto._createPage = function(barView, title, iconUrl, widget, backgroundColor, scrolls) {
  var bt = new qx.ui.pageview.buttonview.Button(title, iconUrl);
  if (barView.getBar().isEmpty()) {
    bt.setChecked(true);
  }

  barView.getBar().add(bt);

  var page = new qx.ui.pageview.buttonview.Page(bt);
  barView.getPane().add(page);

  page.set({ left:0, right:0, top:0, bottom:0 });

  widget.setLocation(0, 0);
  widget.set({ left:0, right:0, bottom:0, right:0 });
  if (!scrolls) {
    widget.set({ height:null, width:null, overflow:"auto" });
  }

  if (backgroundColor) {
    page.setBackgroundColor(backgroundColor);
  }

  page.add(widget);

  return page;
}


qx.Proto._createFormDemo = function() {
  var main = new qx.ui.layout.VerticalBoxLayout;
  main.setPadding(10);

  var groupWidth = 285;

  // fields
  var group1 = new qx.ui.groupbox.GroupBox("Some controls", "icon/16/configure.png");
  group1.setDimension("auto", "auto");
  main.add(group1);

  var gl = new qx.ui.layout.GridLayout;
  group1.add(gl);

  gl.setDimension(groupWidth - 26, "auto");
  gl.setColumnCount(2);
  gl.setRowCount(6);
  gl.setVerticalSpacing(4);
  gl.setHorizontalSpacing(6);

  gl.setColumnWidth(0, 70);
  gl.setColumnWidth(1, 180);

  //gl.setColumnHorizontalAlignment(0, "right");
  gl.setColumnVerticalAlignment(0, "middle");

  gl.setRowHeight(0, 20);
  gl.setRowHeight(1, 20);
  gl.setRowHeight(2, 20);
  gl.setRowHeight(3, 20);
  gl.setRowHeight(4, 70);
  gl.setRowHeight(5, 20);

  gl.add(new qx.ui.basic.Label("Name"), 0, 0);
  gl.add(new qx.ui.form.TextField, 1, 0);
  gl.add(new qx.ui.basic.Label("Amount"), 0, 1);
  gl.add(new qx.ui.form.Spinner, 1, 1);
  gl.add(new qx.ui.basic.Label("Type"), 0, 2);

  var combo = new qx.ui.form.ComboBox;
  combo.add(new qx.ui.form.ListItem("CD"));    //, "icon/16/cd.png"));
  combo.add(new qx.ui.form.ListItem("Clock"));   //, "icon/16/clock.png"));
  combo.add(new qx.ui.form.ListItem("Modem"));   //, "icon/16/modem.png"));
  combo.add(new qx.ui.form.ListItem("Network")); //, "icon/16/network.png"));
  combo.add(new qx.ui.form.ListItem("Sound"));   //, "icon/16/mixer.png"));
  combo.add(new qx.ui.form.ListItem("PDA"));   //, "icon/16/pda.png"));
  combo.add(new qx.ui.form.ListItem("Printer")); //, "icon/16/printer.png"));
  combo.add(new qx.ui.form.ListItem("Scanner")); //, "icon/16/scanner.png"));
  combo.add(new qx.ui.form.ListItem("TV"));    //, "icon/16/tv.png"));
  gl.add(combo, 1, 2);

  gl.add(new qx.ui.basic.Label("E-Mail"), 0, 3);
  gl.add(new qx.ui.form.TextField, 1, 3);

  var label6 = new qx.ui.basic.Label("Comment");
  label6.setVerticalAlign("top");
  label6.setVerticalAlign("top");
  gl.add(label6, 0, 4);

  gl.add(new qx.ui.form.TextArea, 1, 4);

  var input7 = new qx.ui.form.Button("Submit", "icon/16/apply.png");
  input7.setHorizontalAlign("right");
  gl.add(input7, 1, 5);

  // Checkboxes
  var group2 = new qx.ui.groupbox.GroupBox("Some settings");
  group2.setDimension(groupWidth, "auto");
  main.add(group2);

  var bl = new qx.ui.layout.VerticalBoxLayout;
  group2.add(bl);

  bl.add(new qx.ui.form.CheckBox("Permit others to view my favorites"));

  var chb = new qx.ui.form.CheckBox("Use the very high bitrate");
  chb.setChecked(true);
  bl.add(chb);

  // Radio buttons
  var group3 = new qx.ui.groupbox.GroupBox("Network speed", "icon/16/network.png");
  group3.setDimension(groupWidth, "auto");
  main.add(group3);

  var bl = new qx.ui.layout.VerticalBoxLayout;
  group3.add(bl);

  var radio1 = new qx.ui.form.RadioButton("Modem");
  var radio2 = new qx.ui.form.RadioButton("DSL");
  var radio3 = new qx.ui.form.RadioButton("Direct link");
  radio2.setChecked(true);
  bl.add(radio1, radio2, radio3);
  new qx.manager.selection.RadioManager("network", [radio1, radio2, radio3]);

  return main;
}


qx.Proto._createTooltipDemo = function() {
  var main = new qx.ui.layout.HorizontalBoxLayout;
  main.setPadding(10);
  main.setSpacing(10);

  var c1 = new qx.ui.basic.Atom("Hover me", "icon/32/run.png");
  c1.setPadding(5);
  c1.setBorder(qx.renderer.border.BorderPresets.getInstance().outset);
  c1.setBackgroundColor(new qx.renderer.color.Color("#BDD2EF"));
  c1.setToolTip(new qx.ui.popup.ToolTip("Look at this"));
  main.add(c1);

  var c2 = new qx.ui.basic.Atom("Hover me", "icon/32/toys.png");
  c2.setPadding(5);
  c2.setBorder(qx.renderer.border.BorderPresets.getInstance().outset);
  c2.setBackgroundColor(new qx.renderer.color.Color("#D1DFAD"));
  c2.setToolTip(new qx.ui.popup.ToolTip("Images are also possible", "icon/16/help.png"));
  main.add(c2);

  var c3 = new qx.ui.basic.Atom("Hover me", "icon/32/penguin.png");
  c3.setPadding(5);
  c3.setBorder(qx.renderer.border.BorderPresets.getInstance().outset);
  c3.setBackgroundColor(new qx.renderer.color.Color("#D1A4AD"));
  var tip3 = new qx.ui.popup.ToolTip('Such a great tooltip with a show timeout of 50ms.<br>And <b>H</b><span style="color:red">T</span><i>M</i><u>L</u>', "icon/32/penguin.png");
  tip3.setShowInterval(50);
  c3.setToolTip(tip3);
  main.add(c3);

  return main;
}


qx.Proto._createToolbarDemo = function() {
  var doc = qx.ui.core.ClientDocument.getInstance();

  var main = new qx.ui.layout.VerticalBoxLayout;
  main.setPadding(10);

  // Menu
  var m1 = new qx.ui.menu.Menu;
  var mb1_01 = new qx.ui.menu.Button("New", "icon/16/file-new.png");
  var mb1_02 = new qx.ui.menu.Button("Open", "icon/16/file-open.png");
  var mb1_03 = new qx.ui.menu.Button("Save", "icon/16/file-save.png");
  var mb1_04 = new qx.ui.menu.Button("Save as", "icon/16/file-save-as.png");
  var mb1_05 = new qx.ui.menu.Button("Close", "icon/16/stop.png");
  var mb1_06 = new qx.ui.menu.Button("Restore last saved", "icon/16/reload.png");
  m1.add(mb1_01, mb1_02, mb1_03, mb1_04, mb1_05, mb1_06);

  var m2 = new qx.ui.menu.Menu;
  var mb2_01 = new qx.ui.menu.Button("Undo", "icon/16/undo.png");
  var mb2_02 = new qx.ui.menu.Button("Redo", "icon/16/redo.png");
  var mb2_b1 = new qx.ui.menu.Separator();
  var mb2_03 = new qx.ui.menu.Button("Cut", "icon/16/edit-cut.png");
  var mb2_04 = new qx.ui.menu.Button("Copy", "icon/16/edit-copy.png");
  var mb2_05 = new qx.ui.menu.Button("Paste", "icon/16/edit-paste.png");
  var mb2_06 = new qx.ui.menu.Button("Delete", "icon/16/edit-delete.png");
  var mb2_b2 = new qx.ui.menu.Separator();
  var mb2_07 = new qx.ui.menu.Button("Select All");
  var mb2_08 = new qx.ui.menu.Button("Find", "icon/16/find.png");
  var mb2_09 = new qx.ui.menu.Button("Find Again");
  mb2_05.setEnabled(false);
  mb2_06.setEnabled(false);
  mb2_09.setEnabled(false);
  m2.add(mb2_01, mb2_02, mb2_b1, mb2_03, mb2_04, mb2_05, mb2_06, mb2_b2, mb2_07, mb2_08, mb2_09);

  var m3 = new qx.ui.menu.Menu;
  var m3_suba = new qx.ui.menu.Menu;
  var m3_subb = new qx.ui.menu.Menu;
  var m3_subc = new qx.ui.menu.Menu;
  var m3_subd = new qx.ui.menu.Menu;

  var mb3_01 = new qx.ui.menu.CheckBox("File List", null, false);
  var mb3_02 = new qx.ui.menu.CheckBox("Syntax Highlighting", null, true);
  var mb3_03 = new qx.ui.menu.CheckBox("Statusbar", null, true);
  var mb3_b1 = new qx.ui.menu.Separator();
  var mb3_04 = new qx.ui.menu.Button("Printer Font", null, null, m3_suba);
  var mb3_05 = new qx.ui.menu.Button("Editor Font", null, null, m3_subb);
  var mb3_06 = new qx.ui.menu.Button("Export Font", null, null, m3_subc);
  var mb3_b2 = new qx.ui.menu.Separator();
  var mb3_07 = new qx.ui.menu.Button("Advanced", null, null, m3_subd);
  m3.add(mb3_01, mb3_02, mb3_03, mb3_b1, mb3_04, mb3_05, mb3_06, mb3_b2, mb3_07);

  var mb3_suba_01 = new qx.ui.menu.Button("Tahoma, 11pt");
  var mb3_suba_02 = new qx.ui.menu.Button("Tahoma, 12pt");
  var mb3_suba_03 = new qx.ui.menu.Button("Tahoma, 13pt");
  var mb3_suba_04 = new qx.ui.menu.Button("Tahoma, 14pt");
  var mb3_suba_05 = new qx.ui.menu.Button("Tahoma, 15pt");
  m3_suba.add(mb3_suba_01, mb3_suba_02, mb3_suba_03, mb3_suba_04, mb3_suba_05);

  var mb3_subb_01 = new qx.ui.menu.Button("Verdana, 11pt");
  var mb3_subb_02 = new qx.ui.menu.Button("Verdana, 12pt");
  var mb3_subb_03 = new qx.ui.menu.Button("Verdana, 13pt");
  var mb3_subb_04 = new qx.ui.menu.Button("Verdana, 14pt");
  var mb3_subb_05 = new qx.ui.menu.Button("Verdana, 15pt");
  m3_subb.add(mb3_subb_01, mb3_subb_02, mb3_subb_03, mb3_subb_04, mb3_subb_05);

  var mb3_subc_01 = new qx.ui.menu.Button("Courier, 11pt");
  var mb3_subc_02 = new qx.ui.menu.Button("Courier, 12pt");
  var mb3_subc_03 = new qx.ui.menu.Button("Courier, 13pt");
  var mb3_subc_04 = new qx.ui.menu.Button("Courier, 14pt");
  var mb3_subc_05 = new qx.ui.menu.Button("Courier, 15pt");
  m3_subc.add(mb3_subc_01, mb3_subc_02, mb3_subc_03, mb3_subc_04, mb3_subc_05);

  var mb3_subd_02_suba = new qx.ui.menu.Menu();
  var mb3_subd_02_suba_01 = new qx.ui.menu.Button("First");
  var mb3_subd_02_suba_02 = new qx.ui.menu.Button("Second");
  var mb3_subd_02_suba_03 = new qx.ui.menu.Button("Third");
  mb3_subd_02_suba.add(mb3_subd_02_suba_01, mb3_subd_02_suba_02, mb3_subd_02_suba_03);

  var mb3_subd_01 = new qx.ui.menu.Button("First");
  var mb3_subd_02 = new qx.ui.menu.Button("Second", null, null, mb3_subd_02_suba);
  var mb3_subd_03 = new qx.ui.menu.Button("Third");

  m3_subd.add(mb3_subd_01, mb3_subd_02, mb3_subd_03);

  var m4 = new qx.ui.menu.Menu;
  var m4_suba = new qx.ui.menu.Menu;

  var mb4_01 = new qx.ui.menu.Button("View", null, null, m4_suba);
  var mb4_b1 = new qx.ui.menu.Separator();
  var mb4_02 = new qx.ui.menu.Button("Editor Preferences...", "icon/16/configure.png");
  var mb4_03 = new qx.ui.menu.Button("Editor Extensions", "icon/16/connect-established.png");
  var mb4_04 = new qx.ui.menu.Button("Framework Preferences");

  m4.add(mb4_01, mb4_b1, mb4_02, mb4_03, mb4_04);

  var mb4_suba_01 = new qx.ui.menu.Button("New Window");
  var mb4_suba_b1 = new qx.ui.menu.Separator();
  var mb4_suba_02 = new qx.ui.menu.RadioButton("Overlapping", null, true);
  var mb4_suba_03 = new qx.ui.menu.RadioButton("Split Horizontally");
  var mb4_suba_04 = new qx.ui.menu.RadioButton("Split Vertically");
  var mb4_suba_b2 = new qx.ui.menu.Separator();
  var mb4_suba_05 = new qx.ui.menu.Button("Next Window");
  var mb4_suba_06 = new qx.ui.menu.Button("Previous Window");

  m4_suba.add(mb4_suba_01, mb4_suba_b1, mb4_suba_02, mb4_suba_03, mb4_suba_04, mb4_suba_b2, mb4_suba_05, mb4_suba_06);

  var mb4_manager = new qx.manager.selection.RadioManager("windowMode", [ mb4_suba_02, mb4_suba_03, mb4_suba_04 ]);

  var m5 = new qx.ui.menu.Menu;
  var mb5_01 = new qx.ui.menu.Button("Help", "icon/16/help.png");
  var mb5_02 = new qx.ui.menu.Button("About", "icon/16/run.png");
  m5.add(mb5_01, mb5_02);

  doc.add(m1, m2, m3, m3_suba, m3_subb, m3_subc, m3_subd, mb3_subd_02_suba, m4, m4_suba, m5);

  var mb1 = new qx.ui.toolbar.ToolBar;
  var mbb1 = new qx.ui.toolbar.MenuButton("File", m1);
  var mbb2 = new qx.ui.toolbar.MenuButton("Edit", m2);
  var mbb3 = new qx.ui.toolbar.MenuButton("View", m3);
  var mbb4 = new qx.ui.toolbar.MenuButton("Options", m4);
  var mbb5 = new qx.ui.toolbar.MenuButton("Help", m5);
  mb1.add(mbb1, mbb2, mbb3, mbb4, mbb5);
  main.add(mb1);

  // Toolbar
  function changeLayout(e) {
    this.setShow(e.getData());
  }

  function changeSize(e) {
    var v = e.getData();
    var o = v == 22 ? 32 : 22;

    this.setIcon(this.getIcon().replace(o, v));
  }

  function createButton(text, icon, clazz, checked) {
    if (! clazz) {
      clazz = qx.ui.toolbar.Button;
    }

    var button = new clazz(text, "icon/22/" + icon + ".png");
    doc.addEventListener("changeLayout", changeLayout, button);
    doc.addEventListener("changeSize", changeSize, button);

    if (checked) {
      button.setChecked(true);
    }

    return button;
  }

  var tb = new qx.ui.toolbar.ToolBar;
  main.add(tb);

  var part = new qx.ui.toolbar.Part;
  tb.add(part);
  part.add(createButton("New", "file-new"));
  part.add(new qx.ui.toolbar.Separator);
  part.add(createButton("Copy",  "edit-copy"));
  part.add(createButton("Cut",   "edit-cut"));
  part.add(createButton("Paste", "edit-paste"));

  var part = new qx.ui.toolbar.Part;
  tb.add(part);
  part.add(createButton("Check", "configure", qx.ui.toolbar.CheckBox, true));

  var part = new qx.ui.toolbar.Part;
  tb.add(part);
  var radio1 = createButton("Radio1", "view-choose", qx.ui.toolbar.RadioButton);
  var radio2 = createButton("Radio2", "view-detailed", qx.ui.toolbar.RadioButton, true);
  var radio3 = createButton("Radio3", "view-icon", qx.ui.toolbar.RadioButton);
  part.add(radio1, radio2, radio3);
  new qx.manager.selection.RadioManager(null, [radio1, radio2, radio3]);

  // Toolbar manipulation
  var hor = new qx.ui.layout.HorizontalBoxLayout;
  hor.setDimension("auto", "auto");
  hor.set({ spacing:10, marginTop:20 });
  main.add(hor);

  var vert = new qx.ui.layout.VerticalBoxLayout;
  vert.setDimension("auto", "auto");
  hor.add(vert);

  var radio1 = new qx.ui.form.RadioButton("Show Icons and Label", "both");
  var radio2 = new qx.ui.form.RadioButton("Show Icons", "icon");
  var radio3 = new qx.ui.form.RadioButton("Show Label", "label");
  radio1.setChecked(true);
  vert.add(radio1, radio2, radio3);
  var rbm = new qx.manager.selection.RadioManager(null, [radio1, radio2, radio3]);
  rbm.addEventListener("changeSelected", function(e) {
    doc.dispatchEvent( new qx.event.type.DataEvent("changeLayout", e.getData().getValue() ) );
  });

  // Alignment
  var vert = new qx.ui.layout.VerticalBoxLayout;
  vert.setDimension("auto", "auto");
  hor.add(vert);

  var radio1 = new qx.ui.form.RadioButton("Left Aligned", "left");
  var radio2 = new qx.ui.form.RadioButton("Centered", "center");
  var radio3 = new qx.ui.form.RadioButton("Right Aligned", "right");
  radio1.setChecked(true);
  vert.add(radio1, radio2, radio3);
  var rbm = new qx.manager.selection.RadioManager(null, [radio1, radio2, radio3]);
  rbm.addEventListener("changeSelected", function(e) {
    tb.setHorizontalChildrenAlign(e.getData().getValue());
  });

  // Icon Sizes
  var vert = new qx.ui.layout.VerticalBoxLayout;
  vert.setDimension("auto", "auto");
  hor.add(vert);

  var button = new qx.ui.form.Button("Icons: 22 Pixel", "icon/16/colors.png");
  button.setHorizontalAlign("center");
  button.addEventListener("execute", function(e) {
    doc.dispatchEvent(new qx.event.type.DataEvent("changeSize", 22));
  });
  vert.add(button);

  var button = new qx.ui.form.Button("Icons: 32 Pixel", "icon/16/colors.png");
  button.setHorizontalAlign("center");
  button.addEventListener("execute", function(e) {
    doc.dispatchEvent(new qx.event.type.DataEvent("changeSize", 32));
  });
  vert.add(button);

  return main;
}


qx.Proto._createTabDemo = function() {
  var main = new qx.ui.layout.HorizontalBoxLayout;
  main.setPadding(10);
  main.set({ width:"100%", height:"100%", spacing:10 });

  // Tab view
  var tf1 = new qx.ui.pageview.tabview.TabView;
  tf1.set({ width:"1*" });
  main.add(tf1);

  var t1_1 = new qx.ui.pageview.tabview.Button("Edit");
  var t1_2 = new qx.ui.pageview.tabview.Button("Find");
  var t1_3 = new qx.ui.pageview.tabview.Button("Backup");
  t1_1.setChecked(true);
  tf1.getBar().add(t1_1, t1_2, t1_3);

  var p1_1 = new qx.ui.pageview.tabview.Page(t1_1);
  var p1_2 = new qx.ui.pageview.tabview.Page(t1_2);
  var p1_3 = new qx.ui.pageview.tabview.Page(t1_3);
  tf1.getPane().add(p1_1, p1_2, p1_3);

  p1_2.add(new qx.ui.form.TextField("Find Anywhere"));
  p1_3.add(new qx.ui.form.TextField("Backup Input"));

  var c1 = new qx.ui.form.CheckBox("Place bar on top");
  var c2 = new qx.ui.form.CheckBox("Align tabs to left");

  c1.setTop(0);
  c1.setChecked(true);

  c2.setTop(20);
  c2.setChecked(true);

  p1_1.add(c1, c2);

  c1.addEventListener("changeChecked", function(e) {
    tf1.setPlaceBarOnTop(e.getData());
  });

  c2.addEventListener("changeChecked", function(e) {
    tf1.setAlignTabsToLeft(e.getData());
  });

  // Inner tab view
  var tf2 = new qx.ui.pageview.tabview.TabView;
  tf2.set({ left: 0, top: 50, right: 0, bottom: 0 });
  p1_2.add(tf2);

  var t2_1 = new qx.ui.pageview.tabview.Button("Search for Files", "icon/16/file-open.png");
  var t2_2 = new qx.ui.pageview.tabview.Button("Search the Web",   "icon/16/network.png");
  var t2_3 = new qx.ui.pageview.tabview.Button("Search in Mails",  "icon/16/mail.png");
  t2_1.setChecked(true);
  tf2.getBar().add(t2_1, t2_2, t2_3);

  var p2_1 = new qx.ui.pageview.tabview.Page(t2_1);
  var p2_2 = new qx.ui.pageview.tabview.Page(t2_2);
  var p2_3 = new qx.ui.pageview.tabview.Page(t2_3);
  tf2.getPane().add(p2_1, p2_2, p2_3);

  var t2_1 = new qx.ui.form.TextField("Files...");
  var t2_2 = new qx.ui.form.TextField("Web...");
  var t2_3 = new qx.ui.form.TextField("Mails...");

  t2_1.set({ top: 2, left: 0, width: 140 });
  t2_2.set({ top: 2, left: 0, width: 140 });
  t2_3.set({ top: 2, left: 0, width: 140 });

  p2_1.add(t2_1);
  p2_2.add(t2_2);
  p2_3.add(t2_3);

  var b2_1 = new qx.ui.form.Button("Search", "icon/16/search.png");
  var b2_2 = new qx.ui.form.Button("Search", "icon/16/search.png");
  var b2_3 = new qx.ui.form.Button("Search", "icon/16/search.png");

  b2_1.set({ top: 0, left: 150 });
  b2_2.set({ top: 0, left: 150 });
  b2_3.set({ top: 0, left: 150 });

  p2_1.add(b2_1);
  p2_2.add(b2_2);
  p2_3.add(b2_3);

  function dosearch(e) {
    alert("Searching...");
  }

  b2_1.addEventListener("click", dosearch);
  b2_2.addEventListener("click", dosearch);
  b2_3.addEventListener("click", dosearch);

  // Bar view
  var bs = new qx.ui.pageview.buttonview.ButtonView;
  bs.set({ width:"1*", barPosition:"left" });
  main.add(bs);

  var bsb1 = new qx.ui.pageview.buttonview.Button("Display", "icon/16/display.png");
  var bsb2 = new qx.ui.pageview.buttonview.Button("Colorize", "icon/16/colors.png");
  var bsb3 = new qx.ui.pageview.buttonview.Button("Icons", "icon/16/icons.png");
  var bsb4 = new qx.ui.pageview.buttonview.Button("Applications", "icon/16/run.png");
  var bsb5 = new qx.ui.pageview.buttonview.Button("System", "icon/16/display.png");

  bsb1.setChecked(true);

  bsb1.set({ iconPosition: "left", horizontalChildrenAlign: "left" });
  bsb2.set({ iconPosition: "left", horizontalChildrenAlign: "left" });
  bsb3.set({ iconPosition: "left", horizontalChildrenAlign: "left" });
  bsb4.set({ iconPosition: "left", horizontalChildrenAlign: "left" });
  bsb5.set({ iconPosition: "left", horizontalChildrenAlign: "left" });

  bs.getBar().add(bsb1, bsb2, bsb3, bsb4, bsb5);
  bs.getBar().setHorizontalChildrenAlign("center");
  bs.getBar().setVerticalChildrenAlign("bottom");

  var p1 = new qx.ui.pageview.buttonview.Page(bsb1);
  var p2 = new qx.ui.pageview.buttonview.Page(bsb2);
  var p3 = new qx.ui.pageview.buttonview.Page(bsb3);
  var p4 = new qx.ui.pageview.buttonview.Page(bsb4);
  var p5 = new qx.ui.pageview.buttonview.Page(bsb5);
  bs.getPane().add(p1, p2, p3, p4, p5);

  p1.add(new qx.ui.form.TextField("Display Input"));
  p2.add(new qx.ui.form.TextField("Paint Input"));
  p3.add(new qx.ui.form.TextField("Icons Input"));
  p4.add(new qx.ui.form.TextField("Applications Input"));
  p5.add(new qx.ui.form.TextField("System Input"));

  var r1 = new qx.ui.form.RadioButton("Top", "top");
  var r2 = new qx.ui.form.RadioButton("Right", "right");
  var r3 = new qx.ui.form.RadioButton("Bottom", "bottom");
  var r4 = new qx.ui.form.RadioButton("Left", "left", null, true);

  r1.setTop(50);
  r2.setTop(70);
  r3.setTop(90);
  r4.setTop(110);

  p1.add(r1, r2, r3, r4);

  var rm = new qx.manager.selection.RadioManager(null, [r1, r2, r3, r4]);

  rm.addEventListener("changeSelected", function(e) {
    bs.setBarPosition(e.getData().getValue());
  });

  return main;
}


qx.Proto._createTreeDemo = function() {
  var main = new qx.ui.layout.HorizontalBoxLayout;
  main.setPadding(10);
  main.set({ width:"auto", height:"100%", spacing:10 });

  // Workaround: qx.ui.tree.Tree causes an exception when added to a qx.ui.core.Parent that
  //       has no qx.ui.core.Parent. -> So we give the parent a pseudo parent
  var workaround = new qx.ui.layout.HorizontalBoxLayout;
  workaround.add(main);

  var t = new qx.ui.tree.Tree("Root");
  t.set({ backgroundColor:255, border:qx.renderer.border.BorderPresets.getInstance().inset,
    overflow:"scrollY", height:"100%", width:200 });
  main.add(t);

  var te1 = new qx.ui.tree.TreeFolder("Desktop", "icon/16/home.png", "icon/16/home.png");
  t.add(te1);

  var te1_1 = new qx.ui.tree.TreeFolder("Files");
  var te1_2 = new qx.ui.tree.TreeFolder("Workspace");
  var te1_3 = new qx.ui.tree.TreeFolder("Network");
  var te1_4 = new qx.ui.tree.TreeFolder("Trash");
  te1.add(te1_1, te1_2, te1_3, te1_4);
  var te1_2_1 = new qx.ui.tree.TreeFile("Windows (C:)", "icon/16/harddrive.png");
  var te1_2_2 = new qx.ui.tree.TreeFile("Documents (D:)", "icon/16/harddrive.png");
  te1_2.add(te1_2_1, te1_2_2);

  var te2 = new qx.ui.tree.TreeFolder("Inbox");
  t.add(te2);

  var te2_1 = new qx.ui.tree.TreeFolder("Presets");
  var te2_2 = new qx.ui.tree.TreeFolder("Sent");
  var te2_3 = new qx.ui.tree.TreeFolder("Trash", "icon/16/trash.png", "icon/16/trash.png");
  var te2_4 = new qx.ui.tree.TreeFolder("Data");
  var te2_5 = new qx.ui.tree.TreeFolder("Edit");

  var te2_5_1 = new qx.ui.tree.TreeFolder("Chat");
  var te2_5_2 = new qx.ui.tree.TreeFolder("Pustefix");
  var te2_5_3 = new qx.ui.tree.TreeFolder("TINC");
  te2_5.add(te2_5_1, te2_5_2, te2_5_3);

  var te2_5_3_1 = new qx.ui.tree.TreeFolder("Announce");
  var te2_5_3_2 = new qx.ui.tree.TreeFolder("Devel");
  te2_5_3.add(te2_5_3_1, te2_5_3_2);

  var te2_6 = new qx.ui.tree.TreeFolder("Lists");

  var te2_6_1 = new qx.ui.tree.TreeFolder("Relations");
  var te2_6_2 = new qx.ui.tree.TreeFolder("Company");
  var te2_6_3 = new qx.ui.tree.TreeFolder("Questions");
  var te2_6_4 = new qx.ui.tree.TreeFolder("Internal");
  var te2_6_5 = new qx.ui.tree.TreeFolder("Products");
  var te2_6_6 = new qx.ui.tree.TreeFolder("Press");
  var te2_6_7 = new qx.ui.tree.TreeFolder("Development");
  var te2_6_8 = new qx.ui.tree.TreeFolder("Competition");

  te2_6.add(te2_6_1, te2_6_2, te2_6_3, te2_6_4, te2_6_5, te2_6_6, te2_6_7, te2_6_8);

  var te2_7 = new qx.ui.tree.TreeFolder("Personal");

  var te2_7_1 = new qx.ui.tree.TreeFolder("Bugs");
  var te2_7_2 = new qx.ui.tree.TreeFolder("Family");
  var te2_7_3 = new qx.ui.tree.TreeFolder("Projects");
  var te2_7_4 = new qx.ui.tree.TreeFolder("Holiday");

  te2_7.add(te2_7_1, te2_7_2, te2_7_3, te2_7_4);

  var te2_8 = new qx.ui.tree.TreeFolder("Big");

  for (var i = 0; i < 50; i++) {
    te2_8.add(new qx.ui.tree.TreeFolder("Item " + i));
  }

  var te2_9 = new qx.ui.tree.TreeFolder("Spam");

  te2.add(te2_1, te2_2, te2_3, te2_4, te2_5, te2_6, te2_7, te2_8, te2_9);

  // Command frame
  var commandFrame = new qx.ui.groupbox.GroupBox("Control");
  commandFrame.set({ width:"auto", height:"auto" });
  main.add(commandFrame);

  var command = new qx.ui.layout.VerticalBoxLayout;
  command.set({ width:"auto", height:"auto", paddingRight:12 });
  commandFrame.add(command);

  var tCurrentLabel = new qx.ui.basic.Atom("Current Folder: ");
  command.add(tCurrentLabel);

  var tCurrentInput = new qx.ui.form.TextField;
  tCurrentInput.set({ readOnly:true, marginBottom:20 });
  command.add(tCurrentInput);

  t.getManager().addEventListener("changeSelection", function(e) {
    tCurrentInput.setValue(e.getData()[0]._labelObject.getHtml());
  });

  var tDoubleClick = new qx.ui.form.CheckBox("Use double click?");
  tDoubleClick.addEventListener("changeChecked", function(e) {
    t.setUseDoubleClick(e.getData());
  });
  command.add(tDoubleClick);

  var tTreeLines = new qx.ui.form.CheckBox("Use tree lines?");
  tTreeLines.setChecked(true);
  tTreeLines.addEventListener("changeChecked", function(e) { t.setUseTreeLines(e.getData()); });
  command.add(tTreeLines);

  return main;
}


qx.Proto._createListDemo = function() {
  var main = new qx.ui.layout.HorizontalBoxLayout;
  main.setPadding(10);
  main.set({ width:"auto", height:"100%", spacing:10 });

  // List
  var list = new qx.ui.form.List;
  list.set({ height:"100%", width:150, overflow:"scrollY" });
  main.add(list)

  var item;
  for(var i = 1; i <= 35; i++) {
    var iconName;
    switch (parseInt(Math.random() * 5)) {
      case 0: iconName = "folder.png"; break;
      case 1: iconName = "harddrive.png"; break;
      case 2: iconName = "penguin.png"; break;
      case 3: iconName = "pda.png"; break;
      case 4: iconName = "bell.png"; break;
    }
    item = new qx.ui.form.ListItem("Item No " + i, "icon/" + ((i % 4) ? "16" : "48") + "/" + iconName);

    if (!(i % 9)) (item.setEnabled(false));

    list.add(item);
  }

  // Control
  var control = new qx.ui.layout.VerticalBoxLayout;
  control.set({ width:"auto", height:"auto" });
  main.add(control);

  var c1 = new qx.ui.form.CheckBox("Enable Multi-Selection");
  var c2 = new qx.ui.form.CheckBox("Enable Drag-Selection");
  var c3 = new qx.ui.form.CheckBox("Allow Deselection");
  var c4 = new qx.ui.form.CheckBox("Enable Inline Find");
  control.add(c1, c2, c3, c4);

  c1.setChecked(true);
  c2.setChecked(true);
  c3.setChecked(true);
  c4.setChecked(true);

  c1.addEventListener("changeChecked", function(e) {
    list.getManager().setMultiSelection(e.getData());
  });
  c2.addEventListener("changeChecked", function(e) {
    list.getManager().setDragSelection(e.getData());
  });
  c3.addEventListener("changeChecked", function(e) {
    list.getManager().setCanDeselect(e.getData());
  });
  c4.addEventListener("changeChecked", function(e) {
    list.setEnableInlineFind(e.getData());
  });

  var rd1 = new qx.ui.form.RadioButton("Show Label", "label");
  var rd2 = new qx.ui.form.RadioButton("Show Icon", "icon");
  var rd3 = new qx.ui.form.RadioButton("Show Both", "both");
  rd3.setChecked(true);
  control.add(rd1, rd2, rd3);
  var rbm = new qx.manager.selection.RadioManager( name, [rd1, rd2, rd3]);

  rbm.addEventListener("changeSelected", function(e) {
    for (var i = 0; i < list.getChildrenLength(); i++) {
      list.getChildren()[i].setShow(e.getData().getValue());
    }
  });

  return main;
}


qx.Proto._createListViewDemo = function() {
  var main = new qx.ui.layout.HorizontalBoxLayout;
  main.setPadding(10);
  main.set({ width:"auto", height:"100%", spacing:10 });

  var ld = [];
  var lt = [ "Image", "Text", "PDF", "Illustration", "Document" ];

  for (var i = 0, t; i < 1000; i++) {
    t = Math.round(Math.random() * 4);
    ld.push({ name : { html : "E-Mail " + i, icon : "icon/16/email.png", iconWidth : 16, iconHeight : 16 }, size : { text : Math.round(Math.random()*100) + "kb" }, type : { text : lt[t] }, modified : { text : "Nov " + Math.round(Math.random() * 30 + 1) + " 2005" }, rights: { text : "-rw-r--r--" }, open : { uri : "http://www.google.com/search?q=" + i, html : "Open " + i }});
  }

  var lc = {
    name : { label : "Name", width : 120, type : "iconHtml" },
    size: { label : "Size", width : 50, type : "text", align : "right" },
    type : { label : "Type", width : 80, type : "text" },
    modified : { label : "Last Modified", width : 150, type : "text" },
    rights : { label : "Rights", width: 80, type : "text" }
  }

  var lv = new qx.ui.listview.ListView(ld, lc);
  main.add(lv);

  lv.setBorder(qx.renderer.border.BorderPresets.getInstance().shadow);
  lv.setBackgroundColor("white");
  lv.setWidth(600);
  lv.setHeight(350);

  return main;
}


qx.Proto._createTableDemo = function() {
  // table model
  var tableModel = new qx.ui.table.SimpleTableModel();
  tableModel.setColumns([ "ID", "A number", "A date", "Boolean test" ]);
  var rowData = [];
  var now = new Date().getTime();
  var dateRange = 400 * 24 * 60 * 60 * 1000; // 400 days
  for (var row = 0; row < 100; row++) {
    var date = new Date(now + Math.random() * dateRange - dateRange / 2);
    rowData.push([ row, Math.random() * 10000, date, (Math.random() > 0.5) ]);
  }
  tableModel.setData(rowData);
  tableModel.setColumnEditable(1, true);
  tableModel.setColumnEditable(2, true);

  // table
  var table = new qx.ui.table.Table(tableModel);
  with (table) {
    set({ width:"100%", height:"100%" });
    setMetaColumnCounts([1, -1]);
    getSelectionModel().setSelectionMode(qx.ui.table.SelectionModel.MULTIPLE_INTERVAL_SELECTION);
    getTableColumnModel().setDataCellRenderer(3, new qx.ui.table.BooleanDataCellRenderer());
  }

  return table;
}


qx.Proto._createDateChooserDemo = function() {
  var main = new qx.ui.layout.VerticalBoxLayout;

  var chooser = new qx.ui.component.DateChooser;
  chooser.setLocation(10, 10);
  chooser.setWidth("auto");
  chooser.setHeight("auto");
  main.add(chooser);

  return main;
}


qx.Proto._createNativeWindowDemo = function() {
  var main = new qx.ui.layout.VerticalBoxLayout;
  main.setPadding(10);
  main.set({ width:"auto", height:"auto", spacing:5 });

  var win = new qx.client.NativeWindow("http://www.google.com");
  win.setDimension(600, 400);

  var openBt = new qx.ui.form.Button("Open Native Window", "icon/16/wizard.png");
  openBt.addEventListener("click", function() { win.open(); } );
  main.add(openBt);

  // Initial Settings
  var fs1 = new qx.ui.groupbox.GroupBox("Initial Settings");
  fs1.set({ width:250, height:"auto" });
  main.add(fs1);

  var vert = new qx.ui.layout.VerticalBoxLayout;
  vert.set({ width:"auto", height:"auto" });
  fs1.add(vert);

  var chk1 = new qx.ui.form.CheckBox("Resizeable");
  chk1.setChecked(true);
  chk1.addEventListener("changeChecked", function(e) {
    win.setResizeable(e.getData());
  });

  var chk2 = new qx.ui.form.CheckBox("Show Statusbar");
  chk2.setChecked(false);
  chk2.addEventListener("changeChecked", function(e) {
    win.setShowStatusbar(e.getData());
  });

  var chk3 = new qx.ui.form.CheckBox("Show Menubar");
  chk3.setChecked(false);
  chk3.addEventListener("changeChecked", function(e) {
    win.setShowMenubar(e.getData());
  });

  var chk4 = new qx.ui.form.CheckBox("Show Location");
  chk4.setChecked(false);
  chk4.addEventListener("changeChecked", function(e) {
    win.setShowLocation(e.getData());
  });

  var chk5 = new qx.ui.form.CheckBox("Show Toolbar");
  chk5.setChecked(false);
  chk5.addEventListener("changeChecked", function(e) {
    win.setShowToolbar(e.getData());
  });

  var chk6 = new qx.ui.form.CheckBox("Allow Scrollbars");
  chk6.setChecked(true);
  chk6.addEventListener("changeChecked", function(e) {
    win.setAllowScrollbars(e.getData());
  });

  var chk7 = new qx.ui.form.CheckBox("Modal");
  chk7.setChecked(false);
  chk7.addEventListener("changeChecked", function(e) {
    win.setModal(e.getData());
  });

  var chk8 = new qx.ui.form.CheckBox("Dependent");
  chk8.setChecked(true);
  chk8.addEventListener("changeChecked", function(e) {
    win.setDependent(e.getData());
  });

  vert.add(chk1, chk2, chk3, chk4, chk5, chk6, chk7, chk8);

  // Runtime Settings
  var fs2 = new qx.ui.groupbox.GroupBox("Runtime Settings");
  fs2.set({ width:250, height:"auto" });
  main.add(fs2);

  var vert = new qx.ui.layout.VerticalBoxLayout;
  vert.set({ width:"auto", height:"auto", spacing:2 });
  fs2.add(vert);

  var tf1 = new qx.ui.form.TextField("http://www.google.com");
  tf1.setWidth(150);

  var setUrlBt = new qx.ui.form.Button("Set Url", "icon/16/ok.png");
  setUrlBt.addEventListener("click", function() {
    win.setUrl(tf1.getValue());
  });

  var hor = new qx.ui.layout.HorizontalBoxLayout;
  hor.set({ width:"auto", height:"auto", spacing:5,
    verticalChildrenAlign:"middle", marginBottom:10 });
  vert.add(hor);
  hor.add(tf1, setUrlBt);


  var tf2 = new qx.ui.form.TextField("600");
  tf2.setWidth(50);

  var btn2 = new qx.ui.form.Button("Set Width", "icon/16/ok.png");
  btn2.addEventListener("click", function() {
    win.setWidth(parseInt(tf2.getValue()));
  });

  var hor = new qx.ui.layout.HorizontalBoxLayout;
  hor.set({ width:"auto", height:"auto", spacing:5,
    verticalChildrenAlign:"middle" });
  vert.add(hor);
  hor.add(tf2, btn2);


  var tf3 = new qx.ui.form.TextField("400");
  tf3.setWidth(50);

  var btn3 = new qx.ui.form.Button("Set Height", "icon/16/ok.png");
  btn3.addEventListener("click", function() {
    win.setHeight(parseInt(tf3.getValue()));
  });

  var hor = new qx.ui.layout.HorizontalBoxLayout;
  hor.set({ width:"auto", height:"auto", spacing:5,
    verticalChildrenAlign:"middle", marginBottom:10 });
  vert.add(hor);
  hor.add(tf3, btn3);


  var btn4 = new qx.ui.form.Button("Center to screen", "icon/16/display.png");
  btn4.setWidth("100%");
  btn4.addEventListener("click", function() {
    win.centerToScreen()
  });

  var btn5 = new qx.ui.form.Button("Center to screen area", "icon/16/display.png");
  btn5.setWidth("100%");
  btn5.addEventListener("click", function() {
    win.centerToScreenArea()
  });

  var btn6 = new qx.ui.form.Button("Center to opener", "icon/16/display.png");
  btn6.setWidth("100%");
  btn6.addEventListener("click", function() {
    win.centerToOpener()
  });

  vert.add(btn4, btn5, btn6);

  return main;
}


qx.Proto._createInternalWindowDemo = function() {
  var doc = qx.ui.core.ClientDocument.getInstance();

  var main = new qx.ui.layout.CanvasLayout;
  main.setOverflow("hidden");

  // Create the windows
  var w1 = new qx.ui.window.Window("First Window", "icon/16/bell.png");
  w1.setSpace(20, 400, 48, 250);
  main.add(w1);

  var w2 = new qx.ui.window.Window("Second Window", "icon/16/colors.png");
  w2.setSpace(250, "auto", 120, "auto");
  main.add(w2);

  var w3 = new qx.ui.window.Window("Third Window", "icon/16/network.png");
  w3.setSpace(100, "auto", 200, "auto");
  w3.set({ maxWidth:450, maxHeight:400 });
  main.add(w3);

  var wm1 = new qx.ui.window.Window("First Modal Dialog");
  wm1.setSpace(150, 200, 150, 200);
  wm1.setModal(true);
  doc.add(wm1);

  var wm2 = new qx.ui.window.Window("Second Modal Dialog");
  wm2.setSpace(100, 200, 100, 150);
  wm2.set({ modal:true, showClose:false });
  doc.add(wm2);

  // Fill window 1
  var a1 = new qx.ui.basic.Atom("Welcome to your first own Window.<br/>Have fun!", "icon/32/chart.png");
  a1.set({ top: 4, left: 4 });
  w1.add(a1);

  var tf1 = new qx.ui.pageview.tabview.TabView;
  tf1.set({ left: 10, top: 52, right: 10, bottom: 10 });

  var t1_1 = new qx.ui.pageview.tabview.Button("Explore");
  var t1_2 = new qx.ui.pageview.tabview.Button("Internet");
  var t1_3 = new qx.ui.pageview.tabview.Button("Future");

  t1_1.setChecked(true);

  tf1.getBar().add(t1_1, t1_2, t1_3);

  var p1_1 = new qx.ui.pageview.tabview.Page(t1_1);
  var p1_2 = new qx.ui.pageview.tabview.Page(t1_2);
  var p1_3 = new qx.ui.pageview.tabview.Page(t1_3);

  tf1.getPane().add(p1_1, p1_2, p1_3);

  w1.add(tf1);

  // Fill window 2
  var at1 = new qx.ui.basic.Atom("Your second window", "icon/22/find.png");
  at1.setLocation(8, 8);
  w2.add(at1);

  var fs1 = new qx.ui.groupbox.GroupBox("Settings");
  fs1.set({ left:4, top:40, right:4, bottom:4 });

  var chk1 = new qx.ui.form.CheckBox("Show Icon");
  chk1.set({ left:0, top:0, checked:true });
  chk1.addEventListener("changeChecked", function(e) {
    w2.setShowIcon(e.getData());
  });

  var chk2 = new qx.ui.form.CheckBox("Show Caption");
  chk2.set({ left:0, top:20, checked:true });
  chk2.addEventListener("changeChecked", function(e) {
    w2.setShowCaption(e.getData());
  });

  var chk3 = new qx.ui.form.CheckBox("Resizeable");
  chk3.set({ left:0, top:50, checked:true });
  chk3.addEventListener("changeChecked", function(e) {
    w2.setResizeable(e.getData());
  });

  var chk4 = new qx.ui.form.CheckBox("Moveable");
  chk4.set({ left:0, top:70, checked:true });
  chk4.addEventListener("changeChecked", function(e) {
    w2.setMoveable(e.getData());
  });

  var chk5 = new qx.ui.form.CheckBox("Show Close");
  chk5.set({ left:140, top:0, checked:true });
  chk5.addEventListener("changeChecked", function(e) {
    w2.setShowClose(e.getData());
  });

  var chk6 = new qx.ui.form.CheckBox("Show Maximize/Restore");
  chk6.set({ left:140, top:20, checked:true });
  chk6.addEventListener("changeChecked", function(e) {
    w2.setShowMaximize(e.getData());
  });

  var chk7 = new qx.ui.form.CheckBox("Show Minimize");
  chk7.set({ left:140, top:40, checked:true });
  chk7.addEventListener("changeChecked", function(e) {
    w2.setShowMinimize(e.getData());
  });

  var chk8 = new qx.ui.form.CheckBox("Allow Close");
  chk8.set({ left:140, top:70, checked:true });
  chk8.addEventListener("changeChecked", function(e) {
    w2.setAllowClose(e.getData());
  });

  var chk9 = new qx.ui.form.CheckBox("Allow Maximize");
  chk9.set({ left:140, top:90, checked:true });
  chk9.addEventListener("changeChecked", function(e) {
    w2.setAllowMaximize(e.getData());
  });

  var chk10 = new qx.ui.form.CheckBox("Allow Minimize");
  chk10.set({ left:140, top:110, checked:true });
  chk10.addEventListener("changeChecked", function(e) {
    w2.setAllowMinimize(e.getData());
  });

  var l1 = new qx.ui.basic.Atom("Move Method", "icon/16/info.png");
  l1.setLocation(0, 100);

  var rb1 = new qx.ui.form.RadioButton("Frame", "frame");
  rb1.setLocation(0, 120);

  var rb2 = new qx.ui.form.RadioButton("Opaque", "opaque");
  rb2.setLocation(0, 140);
  rb2.setChecked(true);

  var rb3 = new qx.ui.form.RadioButton("Translucent", "translucent");
  rb3.setLocation(0, 160);

  var rbm1 = new qx.manager.selection.RadioManager("move", [rb1, rb2, rb3]);

  rbm1.addEventListener("changeSelected", function(e) {
    w2.setMoveMethod(e.getData().getValue());
  });

  var l2 = new qx.ui.basic.Atom("Resize Method", "icon/16/info.png");
  l2.setLocation(0, 190);

  var rb4 = new qx.ui.form.RadioButton("Frame", "frame");
  rb4.setLocation(0, 210);
  rb4.setChecked(true);

  var rb5 = new qx.ui.form.RadioButton("Opaque", "opaque");
  rb5.setLocation(0, 230);

  var rb6 = new qx.ui.form.RadioButton("Lazy Opaque", "lazyopaque");
  rb6.setLocation(0, 250);

  var rb7 = new qx.ui.form.RadioButton("Translucent", "translucent");
  rb7.setLocation(0, 270);

  var rbm2 = new qx.manager.selection.RadioManager("resize", [rb4, rb5, rb6, rb7]);

  rbm2.addEventListener("changeSelected", function(e) {
    w2.setResizeMethod(e.getData().getValue());
  });

  var chk11 = new qx.ui.form.CheckBox("Show Statusbar");
  chk11.setLocation(140, 140);
  chk11.setChecked(false);
  chk11.addEventListener("changeChecked", function(e) {
    w2.setShowStatusbar(e.getData());
  });

  var btnpack = new qx.ui.form.Button("Pack Window", "icon/16/cdrom.png");
  btnpack.setLocation(140, 170);
  btnpack.addEventListener("execute", function(e) {
    w2.pack();
  });

  fs1.add(chk1, chk2, chk3, chk4, chk5, chk6, chk7, chk8, chk9, chk10, l1, rb1, rb2, rb3, l2, rb4, rb5, rb6, rb7, chk11, btnpack);
  w2.add(fs1);

  // Fill window 3
  var btn1 = new qx.ui.form.Button("Open Modal Dialog 1", "icon/16/launch.png");
  btn1.setLocation(4, 4);
  w3.add(btn1);

  btn1.addEventListener("execute", function(e) {
    wm1.open();
  });

  // Fill modal window 1
  var btn2 = new qx.ui.form.Button("Open Modal Dialog 2", "icon/16/launch.png");
  btn2.setLocation(4, 4);
  wm1.add(btn2);

  btn2.addEventListener("execute", function(e) {
    wm2.open();
  });

  var chkm1 = new qx.ui.form.CheckBox("Modal", null, null, true);
  chkm1.setLocation(4, 50);
  wm1.add(chkm1);

  chkm1.addEventListener("changeChecked", function(e) {
    wm1.setModal(e.getData());
  });

  // Fill modal window 2
  var icon1 = new qx.ui.basic.Image("icon/32/error.png");
  var warn1 = new qx.ui.basic.Label("Do you want to delete<br/>all your personal data?");

  icon1.setTop(10);
  icon1.setLeft(10);

  warn1.setTop(10);
  warn1.setLeft(48);

  var btn3 = new qx.ui.form.Button("Yes", "icon/16/button-ok.png");
  var btn4 = new qx.ui.form.Button("No", "icon/16/button-cancel.png");

  btn3.addEventListener("execute", function(e) {
    alert("Thank you!");
    wm2.close();
  });

  btn4.addEventListener("execute", function(e) {
    alert("Sorry, please click 'Yes'!");
  });

  btn3.set({ bottom : 10, right : 10 });
  btn4.set({ bottom : 10, left : 10 });

  wm2.add(btn3, btn4, icon1, warn1);

  // Icon & Color Themes
  //qx.manager.object.ImageManager.getInstance().createThemeList(w3, 20, 248);
  //qx.manager.object.ColorManager.getInstance().createThemeList(w3, 4, 58);

  w1.open();
  w2.open();
  w3.open();

  return main;
}


qx.Proto._createThemesDemo = function() {
  var doc = qx.ui.core.ClientDocument.getInstance();

  // Theming window
  var win = new qx.ui.window.Window("Theming window", "icon/16/style.png");
  //win.set({ width:"auto", height:"auto" });
  doc.add(win);

  var vert = new qx.ui.layout.VerticalBoxLayout;
  vert.set({ width:"auto", height:"auto", spacing:5, left:0, top:0, right:0, bottom:0 });
  vert.setPadding(10);
  win.add(vert);

  var info = new qx.ui.basic.Atom("Click on one of the buttons and then view the "
    + "other tabs to see the changes", "icon/32/run.png");
  //info.set({ border:qx.renderer.border.BorderPresets.getInstance().inset, backgroundColor:"white" });
  info.setPadding(5);
  vert.add(info);

  var hor = new qx.ui.layout.HorizontalBoxLayout;
  hor.set({ width:"auto", height:"auto", spacing:5 });
  vert.add(hor);

  var can = new qx.ui.layout.CanvasLayout;
  can.set({ width:"auto", height:"auto" });
  hor.add(can);
  qx.manager.object.ImageManager.getInstance().createThemeList(can, 0, 0);

  var can = new qx.ui.layout.CanvasLayout;
  can.set({ width:"auto", height:"auto" });
  hor.add(can);
  qx.manager.object.ColorManager.getInstance().createThemeList(can, 0, 0);

  // Put the window in lower right corner
  win.set({ width:"auto", height:"auto" });

  // Open button
  var main = new qx.ui.layout.VerticalBoxLayout;
  main.setPadding(10);
  main.set({ width:"auto", height:"auto" });

  var openThemeWinBt = new qx.ui.form.Button("Open theming window", "icon/16/launch.png");
  openThemeWinBt.addEventListener("execute", function(e) {
    win.open();

    // the following breaks in the current layouter
    /*
    win.setLeft(doc.getClientWidth() - win.getBoxWidth() - 5);
    win.setTop(doc.getClientHeight() - win.getBoxHeight() - 5);
    */

    win.setLeft(doc.getClientWidth() - 500);
    win.setTop(doc.getClientHeight() - 300);
  });
  main.add(openThemeWinBt);

  return main;
}

