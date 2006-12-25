/**
 * Swat statistics class graphical user interface
 */
qx.OO.defineClass("swat.module.stats.Gui", qx.core.Object,
function()
{
  qx.core.Object.call(this);
});


qx.Proto.buildGui = function(module)
{
  var o;
  var fsm = module.fsm;
  var canvas = module.canvas;

  // Add a message field
  o = new qx.ui.form.TextField("hello world");
  o.setWidth(600);
  canvas.add(o);
  fsm.addObject("message", o);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
