function initGui(fsm)
{
  var o;
  var d = qx.ui.core.ClientDocument.getInstance();

  var vLayout = new qx.ui.layout.VerticalBoxLayout();
  vLayout.setTop(40);
  vLayout.setLeft(20);
  vLayout.setSpacing(4);

  vLayout.add(new qx.ui.basic.Label("URL:"));
  var defaultURL = qx.io.remote.Rpc.makeServerURL();
  if (defaultURL == null)
  {
    defaultURL = "/services/";
  }
  o = new qx.ui.form.TextField(defaultURL);
  vLayout.add(o);
  fsm.addObject("text_url", o);

  vLayout.add(new qx.ui.basic.Label("Service:"));
  o = new qx.ui.form.TextField("qooxdoo.test");
  vLayout.add(o);
  fsm.addObject("text_service", o);

  vLayout.add(new qx.ui.basic.Label("Method:"));
  o = new qx.ui.form.TextField("sleep");
  vLayout.add(o);
  fsm.addObject("text_method", o);

  var hLayout = new qx.ui.layout.HorizontalBoxLayout();
  hLayout.setHeight("auto");
  hLayout.setVerticalChildrenAlign("middle");
  hLayout.setSpacing(4);

  o = new qx.ui.form.TextField("2");
  o.setWidth(200);
  hLayout.add(o);
  fsm.addObject("text_message", o);

  o = new qx.ui.form.Button("Send to server");
  o.addEventListener("execute", fsm.eventListener, fsm);
  hLayout.add(o);
  fsm.addObject("button_send", o);

  o = new qx.ui.form.Button("Abort");
  o.setEnabled(false);
  o.addEventListener("execute", fsm.eventListener, fsm);
  hLayout.add(o);
  fsm.addObject("button_abort", o);

  vLayout.add(hLayout);

  vLayout.add(new qx.ui.basic.Label("Result:"));
  o = new qx.ui.form.TextField("");
  o.setWidth(600);
  vLayout.add(o);
  fsm.addObject("text_result", o);

  var hLayout = new qx.ui.layout.HorizontalBoxLayout();
  hLayout.setHeight("auto");
  hLayout.setVerticalChildrenAlign("middle");
  hLayout.setSpacing(4);

  var o = new qx.ui.basic.Atom("Idle=blue, RPC=red");
  o.setBorder(qx.renderer.border.BorderPresets.getInstance().black);
  o.setColor(new qx.renderer.color.Color("white"));
  o.setWidth(200);
  o.setHeight(30);
  o.setPadding(4);
  hLayout.add(o);
  fsm.addObject("atom_1", o, "group_color_change");

  var o = new qx.ui.basic.Atom("Idle=blue, RPC=red");
  o.setBorder(qx.renderer.border.BorderPresets.getInstance().black);
  o.setColor(new qx.renderer.color.Color("white"));
  o.setWidth(200);
  o.setHeight(30);
  o.setPadding(4);
  hLayout.add(o);
  fsm.addObject("atom_2", o, "group_color_change");

  var o = new qx.ui.basic.Atom("Idle=blue, RPC=red");
  o.setBorder(qx.renderer.border.BorderPresets.getInstance().black);
  o.setColor(new qx.renderer.color.Color("white"));
  o.setWidth(200);
  o.setHeight(30);
  o.setPadding(4);
  hLayout.add(o);
  fsm.addObject("atom_3", o, "group_color_change");

  vLayout.add(hLayout);

  d.add(vLayout);
}
