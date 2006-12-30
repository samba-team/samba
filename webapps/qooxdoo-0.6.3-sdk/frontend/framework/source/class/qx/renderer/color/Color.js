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

#module(ui_core)
#require(qx.util.Return)
#load(qx.renderer.color.ColorObject)

************************************************************************ */

qx.OO.defineClass("qx.renderer.color.Color", qx.core.Object,
function(vValue)
{
  if (qx.util.Validation.isValid(vValue)) {
    this.setValue(vValue);
  }

  qx.core.Object.call(this);
});





/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  CORE METHODS
---------------------------------------------------------------------------
*/

qx.renderer.color.Color.rgb2style = function(r, g, b) {
  return "rgb(" + r + "," + g + "," + b + ")";
}





/*
---------------------------------------------------------------------------
  CORE DATA
---------------------------------------------------------------------------
*/

qx.renderer.color.Color.m_hex = [ "0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f" ];
qx.renderer.color.Color.m_rgb = { 0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,a:10,b:11,c:12,d:13,e:14,f:15 }

qx.renderer.color.Color.r_hex3 = /^#([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})$/;
qx.renderer.color.Color.r_hex6 = /^#([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})([0-9a-f]{1})$/;
qx.renderer.color.Color.r_cssrgb = /^rgb\(\s*([0-9]{1,3}\.{0,1}[0-9]*)\s*,\s*([0-9]{1,3}\.{0,1}[0-9]*)\s*,\s*([0-9]{1,3}\.{0,1}[0-9]*)\s*\)$/;

qx.renderer.color.Color.r_rgb = /^[0-9]{1,3},[0-9]{1,3},[0-9]{1,3}$/;
qx.renderer.color.Color.r_number = /^[0-9]{1,3}\.{0,1}[0-9]*$/;
qx.renderer.color.Color.r_percent = /^[0-9]{1,3}\.{0,1}[0-9]*%$/;

qx.renderer.color.Color.htmlNames =
{
  maroon : [ 128,0,0 ],
  red : [ 255,0,0 ],
  orange : [ 255,165,0 ],
  yellow : [ 255,255,0 ],
  olive : [ 128,128,0 ],
  purple : [ 128,0,128 ],
  fuchsia : [ 255,0,255 ],
  white : [ 255,255,255 ],
  lime : [ 0,255,0 ],
  green : [ 0,128,0 ],
  navy : [ 0,0,128 ],
  blue : [ 0,0,255 ],
  aqua : [ 0,255,255 ],
  teal : [ 0,128,128 ],
  black : [ 0,0,0 ],
  silver : [ 192,192,192 ],
  gray : [ 128,128,128 ],
  transparent : [-1,-1,-1]
}

// TODO: Add some IE related colors (IE 4.x)
// http://msdn.microsoft.com/library/default.asp?url=/workshop/author/dhtml/reference/colors/colors.asp
/*
qx.renderer.color.Color.cssNames =
{

}
*/

/*
  ActiveBorder: Active window border.
  ActiveCaption: Active window caption.

  AppWorkspace: Background color of multiple document interface.
  Background: Desktop background.

  ButtonFace: Face color for three-dimensional display elements.
  ButtonHighlight: Highlight color for three-dimensional display elements (for edges facing away from the light source).
  ButtonShadow: Shadow color for three-dimensional display elements.
  ButtonText: Text on push buttons.

  CaptionText: Text in caption, size box, and scrollbar arrow box.
  GrayText: Grayed (disabled) text.

  Highlight: Item(s) selected in a control.
  HighlightText: Text of item(s) selected in a control.

  InactiveBorder: Inactive window border.
  InactiveCaption: Inactive window caption.
  InactiveCaptionText: Color of text in an inactive caption.

  InfoBackground: Background color for tooltip controls.
  InfoText: Text color for tooltip controls.

  Menu: Menu background.
  MenuText: Text in menus.

  Scrollbar: Scroll bar gray area.

  ThreeDDarkShadow: Dark shadow for three-dimensional display elements.
  ThreeDFace: Face color for three-dimensional display elements.
  ThreeDHighlight: Highlight color for three-dimensional display elements.
  ThreeDLightShadow: Light color for three-dimensional display elements (for edges facing the light source).
  ThreeDShadow: Dark shadow for three-dimensional display elements.

  Window: Window background.
  WindowFrame: Window frame.
  WindowText: Text in windows.
*/

qx.renderer.color.Color.themedNames =
{
  activeborder : 1,
  activecaption : 1,
  appworkspace : 1,
  background : 1,
  buttonface : 1,
  buttonhighlight : 1,
  buttonshadow : 1,
  buttontext : 1,
  captiontext : 1,
  graytext : 1,
  highlight : 1,
  highlighttext : 1,
  inactiveborder : 1,
  inactivecaption : 1,
  inactivecaptiontext : 1,
  infobackground : 1,
  infotext : 1,
  menu : 1,
  menutext : 1,
  scrollbar : 1,
  threeddarkshadow : 1,
  threedface : 1,
  threedhighlight : 1,
  threedlightshadow : 1,
  threedshadow : 1,
  window : 1,
  windowframe : 1,
  windowtext : 1
}







/* ************************************************************************
   Instance data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.renderer.color.Color.fromString = function(vDefString) {
  return new qx.renderer.color.Color(vDefString);
}

qx.renderer.color.Color.fromRandom = function() {
  return new qx.renderer.color.Color([Math.round(255*Math.random()), Math.round(255*Math.random()), Math.round(255*Math.random())]);
}






/*
---------------------------------------------------------------------------
  DATA
---------------------------------------------------------------------------
*/

qx.Proto._value = null;
qx.Proto._style = null;

qx.Proto._isRgbColor = false;
qx.Proto._isHtmlColor = false;
qx.Proto._isThemedColor = false;

qx.Proto._red = null;
qx.Proto._green = null;
qx.Proto._blue = null;

qx.Proto._hex = null;





/*
---------------------------------------------------------------------------
  COMPATIBILITY METHODS
---------------------------------------------------------------------------
*/

qx.Proto.add = qx.util.Return.returnTrue;
qx.Proto.remove = qx.util.Return.returnTrue;






/*
---------------------------------------------------------------------------
  PUBLIC METHODS
---------------------------------------------------------------------------
*/

qx.Proto.isRgbColor = function() {
  return this._isRgbColor;
}

qx.Proto.isHtmlColor = function() {
  return this._isHtmlColor;
}

qx.Proto.isThemedColor = function() {
  return this._isThemedColor;
}




qx.Proto.setValue = function(vValue)
{
  this._normalize(vValue);

  if (this._isThemedColor) {
    throw new Error("Please use qx.renderer.color.ColorObject for themed colors!");
  }
}

qx.Proto.getValue = function() {
  return this._value || "";
}




qx.Proto.getStyle = function()
{
  if (this._style == null) {
    this._evalStyle();
  }

  return this._style;
}

qx.Proto._evalStyle = function()
{
  if (this._isRgbColor)
  {
    this._style = qx.renderer.color.Color.rgb2style(this._red, this._green, this._blue);
  }
  else if (this._isThemedColor)
  {
    this._applyThemedValue();
  }
  else if (this._isHtmlColor)
  {
    this._style = this._value;
  }
  else if (qx.util.Validation.isValid(this._value))
  {
    throw new Error("_evalStyle could not handle non-rgb colors :" + this.getValue() + "!");
  }
}




qx.Proto.getHex = function()
{
  if (this._hex == null) {
    this._evalHex();
  }

  return this._hex;
}

qx.Proto._evalHex = function()
{
  if (this._isRgbColor)
  {
    var a = ["#"];

    var r = this.getRed();
    a.push(qx.renderer.color.Color.m_hex[Math.floor(r/16)]);
    a.push(qx.renderer.color.Color.m_hex[Math.floor(r%16)]);

    var g = this.getGreen();
    a.push(qx.renderer.color.Color.m_hex[Math.floor(g/16)]);
    a.push(qx.renderer.color.Color.m_hex[Math.floor(g%16)]);

    var b = this.getBlue();
    a.push(qx.renderer.color.Color.m_hex[Math.floor(b/16)]);
    a.push(qx.renderer.color.Color.m_hex[Math.floor(b%16)]);

    this._hex = a.join("");
  }
  else
  {
    // TODO
  }
}




qx.Proto.getRed = function()
{
  if (this._red == null) {
    this._evalRgb();
  }

  return this._red;
}

qx.Proto.getGreen = function()
{
  if (this._green == null) {
    this._evalRgb();
  }

  return this._green;
}

qx.Proto.getBlue = function()
{
  if (this._blue == null) {
    this._evalRgb();
  }

  return this._blue;
}




qx.Proto._evalRgb = function()
{
  if (this._isThemedColor)
  {
    this._applyThemedValue();
  }
  else if (this._isHtmlColor)
  {
    var a = qx.renderer.color.Color.htmlNames[this._value];

    this._red = a[0];
    this._green = a[1];
    this._blue = a[2];
  }
  else
  {
    throw new Error("_evalRgb needs implementation!");
  }
}





/*
---------------------------------------------------------------------------
  PRIVATE METHODS
---------------------------------------------------------------------------
*/

qx.Proto._normalize = function(vInValue)
{
  this._isThemedColor = this._isRgbColor = this._isHtmlColor = false;
  this._hex = null;

  var invalid = new Error("Invalid color: " + vInValue);

  switch(typeof vInValue)
  {
    case "string":
      vInValue = vInValue.toLowerCase();

      if (qx.renderer.color.Color.htmlNames[vInValue])
      {
        this._isHtmlColor = true;
      }
      else if (qx.renderer.color.Color.themedNames[vInValue])
      {
        this._isThemedColor = true;
      }
      else if (qx.renderer.color.Color.r_cssrgb.test(vInValue))
      {
        this._red   = parseInt(RegExp.$1);
        this._green = parseInt(RegExp.$2);
        this._blue  = parseInt(RegExp.$3);

        this._isRgbColor = true;
      }
      else if (qx.renderer.color.Color.r_hex3.test(vInValue))
      {
        this._hex = vInValue;

        this._red   = (qx.renderer.color.Color.m_rgb[RegExp.$1] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$1];
        this._green = (qx.renderer.color.Color.m_rgb[RegExp.$2] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$2];
        this._blue  = (qx.renderer.color.Color.m_rgb[RegExp.$3] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$3];

        this._isRgbColor = true;
      }
      else if (qx.renderer.color.Color.r_hex6.test(vInValue))
      {
        this._hex = vInValue;

        this._red   = (qx.renderer.color.Color.m_rgb[RegExp.$1] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$2];
        this._green = (qx.renderer.color.Color.m_rgb[RegExp.$3] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$4];
        this._blue  = (qx.renderer.color.Color.m_rgb[RegExp.$5] * 16) + qx.renderer.color.Color.m_rgb[RegExp.$6];

        this._isRgbColor = true;
      }
      else
      {
        throw invalid;
      }

      break;

    case "number":
      if (vInValue >= 0 && vInValue <= 255)
      {
        this._red = this._green = this._blue = vInValue;
        this._isRgbColor = true;
      }
      else
      {
        throw invalid;
      }

      break;

    case "object":
      if (qx.util.Validation.isValidArray(vInValue) && vInValue.length == 3)
      {
        this._red = vInValue[0];
        this._green = vInValue[1];
        this._blue = vInValue[2];

        this._isRgbColor = true;
        break;
      }

    default:
      throw invalid;
  }

  if (!this._isRgbColor)
  {
    this._red = this._green = this._blue = null;
    this._style = this._isHtmlColor ? vInValue : null;
  }
  else
  {
    this._style = null;

    if (!(this._red >= 0 && this._red <= 255 && this._green >= 0 && this._green <= 255 && this._blue >= 0 && this._blue <= 255)) {
      throw invalid;
    }
  }

  return this._value = vInValue;
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  delete this._value;
  delete this._style;

  delete this._red;
  delete this._green;
  delete this._blue;

  delete this._isRgbColor;
  delete this._isHtmlColor;
  delete this._isThemedColor;

  return qx.core.Object.prototype.dispose.call(this);
}
