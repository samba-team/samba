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

/**
 * Crossbrowser operations on DOM Elements
 */
qx.OO.defineClass("qx.dom.Element");


/**
 * Removes whitespace-only text node children
 *
 * @param vElement {Element} DOM element
 */
qx.Class.cleanWhitespace = function(vElement)
{
  for (var i=0; i<vElement.childNodes.length; i++)
  {
    var node = vElement.childNodes[i];

    if (node.nodeType == qx.dom.Node.TEXT && !/\S/.test(node.nodeValue)) {
      vElement.removeChild(node);
    }
  }
}


/**
 * Checks if a element has no content
 *
 * @param vElement {Element} DOM element
 */
qx.Class.isEmpty = function(vElement) {
  return vElement.innerHTML.match(/^\s*$/);
}


/**
 * Returns the text content of a DOM element
 * http://developer.mozilla.org/en/docs/DOM:element.textContent
 *
 * @param element {Element} DOM element
 * @return {String}
 */
 qx.Class.getTextContent = function(element) {
  var text = "";
  var childNodes = element.childNodes;
  for (var i=0; i<childNodes.length; i++) {
    var node = childNodes[i];
    if (node.nodeType == qx.dom.Node.TEXT || node.nodeType == qx.dom.Node.CDATA_SECTION) {
      text += node.nodeValue;
    }
  }
  return text;
};


/**
 * Sets the textValue of the given DOM element (http://www.w3.org/TR/2004/REC-DOM-Level-3-Core-20040407/core.html#Node3-textContent).
 * Wrapper for element.innerText and element.textContent.
 *
 * @param vElement {Element} DOM element
 * @param sValue {String} the value
 */
qx.Class.setTextContent = function(vElement, sValue) {};

if (qx.core.Client.getInstance().supportsTextContent()) {
  qx.Class.setTextContent = function(vElement, sValue) {
    vElement.textContent = sValue;
  };
} else if (qx.core.Client.getInstance().supportsInnerText()) {
  qx.Class.setTextContent = function(vElement, sValue) {
    vElement.innerText = sValue;
  };
} else {
  qx.Class.setTextContent = function(vElement, sValue) {
    vElement.innerHTML = qx.html.String.escape(sValue);
  };
}
