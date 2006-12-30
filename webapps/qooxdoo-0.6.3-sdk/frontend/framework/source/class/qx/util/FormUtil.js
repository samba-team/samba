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

#module(io_remote)

************************************************************************ */

qx.OO.defineClass("qx.util.FormUtil");

qx.Class.ignoreInputTypes = [ "file", "submit", "image", "reset", "button" ];
qx.Class.ignoreElementTypes = [ "fieldset" ];
qx.Class.checkElementTypes = [ "radio", "checkbox" ];
qx.Class.multiSelectType = "select-multiple";

qx.Class.inputFilter = function(vNode)
{
  if (vNode.disabled) {
    return false;
  }

  var vTag = (vNode.tagName || "").toLowerCase();

  if (qx.lang.Array.contains(qx.util.FormUtil.ignoreElementTypes, vTag)) {
    return false;
  }

  var vType = vNode.type.toLowerCase();

  if (qx.lang.Array.contains(qx.util.FormUtil.ignoreInputTypes, vType)) {
    return false;
  }

  if (!vNode.checked && qx.lang.Array.contains(qx.util.FormUtil.checkElementTypes, vType)) {
    return false;
  }

  return true;
}

qx.Class.getFields = function(vForm) {
  return Array.filter(vForm.elements, qx.util.FormUtil.inputFilter);
}

qx.Class.encodeField = function(vNode)
{
  var vName = vNode.name || "";
  var vType = (vNode.type || "").toLowerCase();

  if(vType === qx.util.FormUtil.multiSelectType)
  {
    var vValues = [];

    for(var i=0; i<vNode.options.length; i++)
    {
      if(vNode.options[i].selected) {
        vValues.push(vName + "=" + vNode.options[i].value);
      }
    }

    return vValues.join("&");
  }
  else
  {
    return vName + "=" + vNode.value;
  }
}

qx.Class.encodeForm = function(vForm)
{
  var vFields = qx.util.FormUtil.getFields(vForm);
  var vAll = [];

  for (var i=0, l=vFields.length; i<l; i++) {
    vAll.push(qx.util.FormUtil.encodeField(vFields[i]));
  }

  return vAll.join("&");
}

qx.Class.bind = function(vForm, vMethod)
{
  qx.dom.EventRegistration.addEventListener(vForm, "submit", function(e)
  {
    e.returnValue = false;

    if (typeof e.preventDefault === "function") {
      e.preventDefault();
    }

    return vMethod(e);
  });
}
