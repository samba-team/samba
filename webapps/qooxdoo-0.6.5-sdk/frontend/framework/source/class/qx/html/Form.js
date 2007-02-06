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

#module(io_remote)

************************************************************************ */

qx.OO.defineClass("qx.html.Form");

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

  if (qx.lang.Array.contains(qx.html.Form.ignoreElementTypes, vTag)) {
    return false;
  }

  var vType = vNode.type.toLowerCase();

  if (qx.lang.Array.contains(qx.html.Form.ignoreInputTypes, vType)) {
    return false;
  }

  if (!vNode.checked && qx.lang.Array.contains(qx.html.Form.checkElementTypes, vType)) {
    return false;
  }

  return true;
}

qx.Class.getFields = function(vForm) {
  return Array.filter(vForm.elements, qx.html.Form.inputFilter);
}

qx.Class.encodeField = function(vNode)
{
  var vName = vNode.name || "";
  var vType = (vNode.type || "").toLowerCase();

  if(vType === qx.html.Form.multiSelectType)
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
  var vFields = qx.html.Form.getFields(vForm);
  var vAll = [];

  for (var i=0, l=vFields.length; i<l; i++) {
    vAll.push(qx.html.Form.encodeField(vFields[i]));
  }

  return vAll.join("&");
}

qx.Class.bind = function(vForm, vMethod)
{
  qx.html.EventRegistration.addEventListener(vForm, "submit", function(e)
  {
    e.returnValue = false;

    if (typeof e.preventDefault === "function") {
      e.preventDefault();
    }

    return vMethod(e);
  });
}
