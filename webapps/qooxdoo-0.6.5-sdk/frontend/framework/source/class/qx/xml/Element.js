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
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

/**
 * XML Element
 *
 * Tested with IE6, Firefox 2.0, WebKit/Safari 3.0 and Opera 9
 *
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/xmlsdk/html/81f3de54-3b79-46dc-8e01-73ca2d94cdb5.asp
 * http://developer.mozilla.org/en/docs/Parsing_and_serializing_XML
 */
qx.OO.defineClass("qx.xml.Element");


/**
 * The subtree rooted by the specified element or document is serialized to a string.
 *
 * @param element {Element|Document} The root of the subtree to be serialized. This could be any node, including a Document.
 * @return {String}
 */
qx.Class.serialize = function(element) {}

if (window.XMLSerializer) {
  qx.Class.serialize = function(element) {
    var element = qx.xml.Document.isDocument(element) ? element.documentElement : element;
    return (new XMLSerializer()).serializeToString(element);
  };
}
else
{
  qx.Class.serialize = function(element) {
    var element = qx.xml.Document.isDocument(element) ? element.documentElement : element;
    return element.xml || element.outerHTML;
  };
}


/**
 * Selects the first XmlNode that matches the XPath expression.
 *
 * @param element {Element|Document} root element for the search
 * @param query {String}  XPath query
 * @return {Element} first matching element
 */
 qx.Class.selectSingleNode = function(element, query) {};

if (window.XPathEvaluator)
{
  qx.Class.selectSingleNode = function(element, query) {
    var xpe = new XPathEvaluator();
    return xpe.evaluate(query, element, xpe.createNSResolver(element), XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
  };
}
else if(qx.core.Client.getInstance().isMshtml() || document.selectSingleNode) // IE and Opera
{
  qx.Class.selectSingleNode = function(element, query) {
    return element.selectSingleNode(query);
  };
}


/**
 * Selects a list of nodes matching the XPath expression.
 *
 * @param element {Element|Document} root element for the search
 * @param query {String}  XPath query
 * @return {Element[]} List of matching elements
 */
 qx.Class.selectNodes = function(element, query) {};

if (window.XPathEvaluator)
{
  qx.Class.selectNodes = function(element, query) {
    var xpe = new XPathEvaluator();
    var result = xpe.evaluate(query, element, xpe.createNSResolver(element), XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
    var nodes = [];

    for (var i=0; i<result.snapshotLength; i++) {
      nodes[i] = result.snapshotItem(i);
    }

    return nodes;
  };
}
else if(qx.core.Client.getInstance().isMshtml() || document.selectNodes) // IE and Opera
{
  qx.Class.selectNodes = function(element, query) {
    return element.selectNodes(query);
  };
}


/**
 * Returns a list of elements with the given tag name belonging to the given namespace (http://developer.mozilla.org/en/docs/DOM:element.getElementsByTagNameNS).
 *
 * @param element {Element|Document} the element from where the search should start.
 *     Note that only the descendants of this element are included in the search, not the node itself.
 * @param namespaceURI is the namespace URI of elements to look for . For example, if you need to look
 *     for XHTML elements, use the XHTML namespace URI, <tt>http://www.w3.org/1999/xhtml</tt>.
 * @param tagname {String} the tagname to look for
 * @return {Element[]} a list of found elements in the order they appear in the tree.
 */
qx.Class.getElementsByTagNameNS = function(element, namespaceURI, tagname) {};

if (document.getElementsByTagNameNS)
{
  qx.Class.getElementsByTagNameNS = function(element, namespaceURI, tagname) {
   return element.getElementsByTagNameNS(namespaceURI, tagname);
  };
}
else if (qx.core.Client.getInstance().isMshtml())
{
  qx.Class.getElementsByTagNameNS = function(element, namespaceURI, tagname) {
    var doc = element.ownerDocument || element;
    doc.setProperty("SelectionLanguage", "XPath");
    doc.setProperty("SelectionNamespaces", "xmlns:ns='" + namespaceURI + "'");
    return qx.xml.Element.selectNodes(element, '//ns:' + tagname);
  };
}
