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
#require(qx.sys.Client)
#load(qx.renderer.border.BorderObject)

************************************************************************ */

/*!
  Border implementation for qx.ui.core.Widget instances.
*/
qx.OO.defineClass("qx.renderer.border.Border", qx.core.Object,
function(vWidth, vStyle, vColor)
{
  qx.core.Object.call(this);

  this._themedEdges = {};
  this._initCache();

  if (qx.util.Validation.isValidNumber(vWidth))
  {
    this.setWidth(vWidth);

    if (qx.util.Validation.isValidString(vStyle)) {
      this.setStyle(vStyle);
    }

    if (qx.util.Validation.isValid(vColor)) {
      this.setColor(vColor);
    }
  }
});


qx.Class.enhancedCrossBrowserMode = true;

qx.Proto._needsCompilationTop = true;
qx.Proto._needsCompilationRight = true;
qx.Proto._needsCompilationBottom = true;
qx.Proto._needsCompilationLeft = true;




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "topWidth", type : "number", defaultValue : 0, impl : "borderTopProperty" });
qx.OO.addProperty({ name : "rightWidth", type : "number", defaultValue : 0, impl : "borderRightProperty" });
qx.OO.addProperty({ name : "bottomWidth", type : "number", defaultValue : 0, impl : "borderBottomProperty" });
qx.OO.addProperty({ name : "leftWidth", type : "number", defaultValue : 0, impl : "borderLeftProperty" });

qx.OO.addProperty({ name : "topStyle", type : "string", defaultValue : "none", impl : "borderTopProperty" });
qx.OO.addProperty({ name : "rightStyle", type : "string", defaultValue : "none", impl : "borderRightProperty" });
qx.OO.addProperty({ name : "bottomStyle", type : "string", defaultValue : "none", impl : "borderBottomProperty" });
qx.OO.addProperty({ name : "leftStyle", type : "string", defaultValue : "none", impl : "borderLeftProperty" });

qx.OO.addProperty({ name : "topColor", impl : "borderTopProperty", type : "object", instance : "qx.renderer.color.Color", convert : qx.renderer.color.ColorCache });
qx.OO.addProperty({ name : "rightColor", impl : "borderRightProperty", type : "object", instance : "qx.renderer.color.Color", convert : qx.renderer.color.ColorCache });
qx.OO.addProperty({ name : "bottomColor", impl : "borderBottomProperty", type : "object", instance : "qx.renderer.color.Color", convert : qx.renderer.color.ColorCache });
qx.OO.addProperty({ name : "leftColor", impl : "borderLeftProperty", type : "object", instance : "qx.renderer.color.Color", convert : qx.renderer.color.ColorCache });




/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.renderer.border.Border.fromString = function(vDefString)
{
  var vBorder = new qx.renderer.border.Border;
  var vAllParts = vDefString.split(/\s+/);
  var vPart, vTemp;

  for (var i=0; i<vAllParts.length; i++)
  {
    switch(vPart = vAllParts[i])
    {
      case "groove":
      case "ridge":
      case "inset":
      case "outset":
      case "solid":
      case "dotted":
      case "dashed":
      case "double":
      case "none":
        vBorder.setStyle(vPart);
        break;

      default:
        vTemp = parseFloat(vPart);

        if(vTemp == vPart || qx.lang.String.contains(vPart, "px"))
        {
          vBorder.setWidth(vTemp);
        }
        else
        {
          vPart = vPart.toLowerCase();
          vBorder.setColor(new qx.renderer.color.Color(vPart));
        }

        break;
    }
  }

  return vBorder;
}





/*
---------------------------------------------------------------------------
  COMPATIBILITY TO qx.renderer.border.BorderOBJECT
---------------------------------------------------------------------------
*/

qx.Proto.addListenerWidget = qx.util.Return.returnTrue;
qx.Proto.removeListenerWidget = qx.util.Return.returnTrue;

qx.Proto._sync = qx.util.Return.returnTrue;





/*
---------------------------------------------------------------------------
  COMBINED SETTERS
---------------------------------------------------------------------------
*/

qx.Proto.setWidth = function(vWidth)
{
  this.setTopWidth(vWidth);
  this.setRightWidth(vWidth);
  this.setBottomWidth(vWidth);
  this.setLeftWidth(vWidth);

  return true;
}

qx.Proto.setStyle = function(vStyle)
{
  this.setTopStyle(vStyle);
  this.setRightStyle(vStyle);
  this.setBottomStyle(vStyle);
  this.setLeftStyle(vStyle);

  return true;
}

qx.Proto.setColor = function(vColor)
{
  this.setTopColor(vColor);
  this.setRightColor(vColor);
  this.setBottomColor(vColor);
  this.setLeftColor(vColor);

  return true;
}




qx.Proto.setTop = function(vWidth, vStyle, vColor)
{
  this.setTopWidth(vWidth);
  this.setTopStyle(vStyle);
  this.setTopColor(vColor);

  return true;
}

qx.Proto.setRight = function(vWidth, vStyle, vColor)
{
  this.setRightWidth(vWidth);
  this.setRightStyle(vStyle);
  this.setRightColor(vColor);

  return true;
}

qx.Proto.setBottom = function(vWidth, vStyle, vColor)
{
  this.setBottomWidth(vWidth);
  this.setBottomStyle(vStyle);
  this.setBottomColor(vColor);

  return true;
}

qx.Proto.setLeft = function(vWidth, vStyle, vColor)
{
  this.setLeftWidth(vWidth);
  this.setLeftStyle(vStyle);
  this.setLeftColor(vColor);

  return true;
}





/*
---------------------------------------------------------------------------
  INITIALISATION OF CACHE
---------------------------------------------------------------------------
*/


if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._initCache = function()
  {
    this._defsX =
    {
      borderLeft : "",
      borderRight : "",

      MozBorderLeftColors : "",
      MozBorderRightColors : ""
    }

    this._defsY =
    {
      borderTop : "",
      borderBottom : "",

      MozBorderTopColors : "",
      MozBorderBottomColors : ""
    }
  }
}
else
{
  qx.Proto._initCache = function()
  {
    this._defsX =
    {
      borderLeft : "",
      borderRight : ""
    }

    this._defsY =
    {
      borderTop : "",
      borderBottom : ""
    }

    if (qx.renderer.border.Border.enhancedCrossBrowserMode)
    {
      this._enhancedDefsX =
      {
        borderLeft : "",
        borderRight : ""
      }

      this._enhancedDefsY =
      {
        borderTop : "",
        borderBottom : ""
      }
    }
  }
}


/*
---------------------------------------------------------------------------
  BORDER MODIFIER AND SYNCER
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isGecko() || qx.renderer.border.Border.enhancedCrossBrowserMode)
{
  qx.Proto._addToThemed3DColors = function(vProp)
  {
    var needRegistering = qx.lang.Object.isEmpty(this._themedEdges);

    this._themedEdges[vProp] = true;

    if (needRegistering)
    {
      (new qx.renderer.color.ColorObject("ThreeDDarkShadow")).add(this);
      (new qx.renderer.color.ColorObject("ThreeDShadow")).add(this);
      (new qx.renderer.color.ColorObject("ThreeDLightShadow")).add(this);
      (new qx.renderer.color.ColorObject("ThreeDHighlight")).add(this);
    }
  }

  qx.Proto._removeFromThemed3DColors = function(vProp)
  {
    delete this._themedEdges[vProp];

    if (qx.lang.Object.isEmpty(this._themedEdges))
    {
      (new qx.renderer.color.ColorObject("ThreeDDarkShadow")).remove(this);
      (new qx.renderer.color.ColorObject("ThreeDShadow")).remove(this);
      (new qx.renderer.color.ColorObject("ThreeDLightShadow")).remove(this);
      (new qx.renderer.color.ColorObject("ThreeDHighlight")).remove(this);
    }
  }
}
else
{
  qx.Proto._addToThemed3DColors = function(vProp)
  {
    var needRegistering = qx.lang.Object.isEmpty(this._themedEdges);

    this._themedEdges[vProp] = true;

    if (needRegistering)
    {
      (new qx.renderer.color.ColorObject("ThreeDLightShadow")).add(this);
    }
  }

  qx.Proto._removeFromThemed3DColors = function(vProp)
  {
    delete this._themedEdges[vProp];

    if (qx.lang.Object.isEmpty(this._themedEdges))
    {
      (new qx.renderer.color.ColorObject("ThreeDLightShadow")).remove(this);
    }
  }
}





qx.renderer.border.Border.data =
{
  1 :
  {
    outset :
    {
      top : [ "threedhighlight" ],
      right : [ "threedshadow" ],
      bottom : [ "threedshadow" ],
      left : [ "threedhighlight" ]
    },

    inset :
    {
      top : [ "threedshadow" ],
      right : [ "threedhighlight" ],
      bottom : [ "threedhighlight" ],
      left : [ "threedshadow" ]
    }
  },

  2 :
  {
    outset :
    {
      top : [ "threedlightshadow", "threedhighlight" ],
      right : [ "threeddarkshadow", "threedshadow" ],
      bottom : [ "threeddarkshadow", "threedshadow" ],
      left : [ "threedlightshadow", "threedhighlight" ]
    },

    inset :
    {
      top : [ "threedshadow", "threeddarkshadow" ],
      right : [ "threedhighlight", "threedlightshadow" ],
      bottom : [ "threedhighlight", "threedlightshadow" ],
      left : [ "threedshadow", "threeddarkshadow" ]
    },

    ridge :
    {
      top : [ "threedhighlight", "threedshadow" ],
      right : [ "threedshadow", "threedhighlight" ],
      bottom : [ "threedshadow", "threedhighlight" ],
      left : [ "threedhighlight", "threedshadow" ]
    },

    groove :
    {
      top : [ "threedshadow", "threedhighlight" ],
      right : [ "threedhighlight", "threedshadow" ],
      bottom : [ "threedhighlight", "threedshadow" ],
      left : [ "threedshadow", "threedhighlight" ]
    }
  }
}





qx.Proto._generateDefString = function(vWidth, vStyle, vColor)
{
  if (typeof vWidth !== "number" || vWidth < 0) {
    return "";
  }

  var vArr = [ vWidth + "px" ];

  if (qx.util.Validation.isValidString(vStyle)) {
    vArr.push(vStyle);
  }

  if (qx.util.Validation.isValidObject(vColor) && vColor instanceof qx.renderer.color.Color) {
    vColor = vColor.getStyle();
  }

  if (qx.util.Validation.isValidString(vColor)) {
    vArr.push(vColor);
  }

  return vArr.join(" ");
}




// TODO: Add more smartness ;)
// Only update the border edges which depends on this color object
qx.Proto._updateColors = function(vColorObject, vNewValue)
{
  this._needsCompilationTop = true;
  this._needsCompilationRight = true;
  this._needsCompilationBottom = true;
  this._needsCompilationLeft = true;

  this._sync("top");
  this._sync("right");
  this._sync("bottom");
  this._sync("left");
}







qx.Proto._handleColorRegistration = function(propValue, propOldValue, propData)
{
  if (qx.lang.String.contains(propData.name, "Style"))
  {
    switch(propValue)
    {
      case "outset":
      case "inset":
      case "groove":
      case "ridge":
        this._addToThemed3DColors(propData.name);
        break;

      default:
        this._removeFromThemed3DColors(propData.name);
    }
  }

  if (qx.lang.String.contains(propData.name, "Color"))
  {
    if (propOldValue instanceof qx.renderer.color.ColorObject)
    {
      // detect if there are no other deps anymore
      switch(propOldValue)
      {
        case this.getTopColor():
        case this.getRightColor():
        case this.getBottomColor():
        case this.getLeftColor():
          break;

        default:
          propOldValue.remove(this);
      }
    }

    if (propValue instanceof qx.renderer.color.ColorObject)
    {
      // simply add, internal storage is a hash key so
      // this is not a problem also if this is already
      // registered there.
      propValue.add(this);
    }
  }
}








qx.Proto._modifyBorderTopProperty = function(propValue, propOldValue, propData)
{
  this._handleColorRegistration(propValue, propOldValue, propData);

  this._needsCompilationTop = true;
  this._useEnhancedCrossBrowserMode = null;

  this._sync("top");

  return true;
}

qx.Proto._modifyBorderRightProperty = function(propValue, propOldValue, propData)
{
  this._handleColorRegistration(propValue, propOldValue, propData);

  this._needsCompilationRight = true;
  this._useEnhancedCrossBrowserMode = null;

  this._sync("right");

  return true;
}

qx.Proto._modifyBorderBottomProperty = function(propValue, propOldValue, propData)
{
  this._handleColorRegistration(propValue, propOldValue, propData);

  this._needsCompilationBottom = true;
  this._useEnhancedCrossBrowserMode = null;

  this._sync("bottom");

  return true;
}

qx.Proto._modifyBorderLeftProperty = function(propValue, propOldValue, propData)
{
  this._handleColorRegistration(propValue, propOldValue, propData);

  this._needsCompilationLeft = true;
  this._useEnhancedCrossBrowserMode = null;

  this._sync("left");

  return true;
}









qx.Proto.getUseEnhancedCrossBrowserMode = function()
{
  if (this._useEnhancedCrossBrowserMode == null) {
    this._useEnhancedCrossBrowserMode = this._evalUseEnhancedCrossBrowserMode();
  }

  return this._useEnhancedCrossBrowserMode;
}

qx.Proto._evalUseEnhancedCrossBrowserMode = function()
{
  if (this.getTopWidth() == 2) {
    switch(this.getTopStyle()) {
      case "outset": case "inset": case "groove": case "ridge": return true;
    }
  }

  if (this.getRightWidth() == 2) {
    switch(this.getRightStyle()) {
      case "outset": case "inset": case "groove": case "ridge": return true;
    }
  }

  if (this.getBottomWidth() == 2) {
    switch(this.getBottomStyle()) {
      case "outset": case "inset": case "groove": case "ridge": return true;
    }
  }

  if (this.getLeftWidth() == 2) {
    switch(this.getLeftStyle()) {
      case "outset": case "inset": case "groove": case "ridge": return true;
    }
  }

  return false;
}






/*
---------------------------------------------------------------------------
  BORDER APPLY IMPLEMENTATION
---------------------------------------------------------------------------
*/

qx.Proto._applyWidget = function(o)
{
  this._applyWidgetX(o);
  this._applyWidgetY(o);
}

qx.Proto._resetWidget = function(o)
{
  this._resetWidgetX(o);
  this._resetWidgetY(o);
}

qx.Proto._resetWidgetX = function(o) {
  return qx.renderer.border.Border._resetBorderX(o);
}

qx.Proto._resetWidgetY = function(o) {
  return qx.renderer.border.Border._resetBorderY(o);
}

qx.Proto._applyWidgetXCommon = function(vObject)
{
  if (this._needsCompilationLeft) {
    this._compileLeft();
  }

  if (this._needsCompilationRight) {
    this._compileRight();
  }

  for (var i in this._defsX) {
    vObject._style[i] = this._defsX[i];
  }

  if (!qx.sys.Client.getInstance().isGecko() && qx.renderer.border.Border.enhancedCrossBrowserMode)
  {
    if (this.getUseEnhancedCrossBrowserMode()) {
      vObject._createElementForEnhancedBorder();
    }

    if (vObject._borderStyle)
    {
      for (var i in this._enhancedDefsX) {
        vObject._borderStyle[i] = this._enhancedDefsX[i];
      }
    }
  }
}

qx.Proto._applyWidgetYCommon = function(vObject)
{
  if (this._needsCompilationTop) {
    this._compileTop();
  }

  if (this._needsCompilationBottom) {
    this._compileBottom();
  }

  for (var i in this._defsY) {
    vObject._style[i] = this._defsY[i];
  }

  if (!qx.sys.Client.getInstance().isGecko() && qx.renderer.border.Border.enhancedCrossBrowserMode)
  {
    if (this.getUseEnhancedCrossBrowserMode()) {
      vObject._createElementForEnhancedBorder();
    }

    if (vObject._borderStyle)
    {
      for (var i in this._enhancedDefsY) {
        vObject._borderStyle[i] = this._enhancedDefsY[i];
      }
    }
  }
}

if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._applyWidgetX = qx.Proto._applyWidgetXCommon;
  qx.Proto._applyWidgetY = qx.Proto._applyWidgetYCommon;

  qx.Proto._generateMozColorDefString = function(vWidth, vStyle, vEdge)
  {
    try
    {
      try {
        var a = qx.renderer.border.Border.data[vWidth][vStyle][vEdge];
      } catch(ex) {}

      if (typeof a === "object")
      {
        for (var i=0, s=[], l=a.length; i<l; i++) {
          s.push((new qx.renderer.color.ColorObject(a[i]).getStyle()));
        }

        return s.join(" ");
      }
    }
    catch(ex) {
      this.error("Failed to generate Mozilla Color Definition Strings", ex);
    }

    return "";
  }

  qx.Proto._compileTop = function()
  {
    var w=this.getTopWidth(), s=this.getTopStyle(), d=this._defsY;

    d.borderTop = this._generateDefString(w, s, this.getTopColor());
    d.MozBorderTopColors = this._generateMozColorDefString(w, s, "top");

    this._needsCompilationTop = false;
  }

  qx.Proto._compileRight = function()
  {
    var w=this.getRightWidth(), s=this.getRightStyle(), d=this._defsX;

    d.borderRight = this._generateDefString(w, s, this.getRightColor());
    d.MozBorderRightColors = this._generateMozColorDefString(w, s, "right");

    this._needsCompilationRight = false;
  }

  qx.Proto._compileBottom = function()
  {
    var w=this.getBottomWidth(), s=this.getBottomStyle(), d=this._defsY;

    d.borderBottom = this._generateDefString(w, s, this.getBottomColor());
    d.MozBorderBottomColors = this._generateMozColorDefString(w, s, "bottom");

    this._needsCompilationBottom = false;
  }

  qx.Proto._compileLeft = function()
  {
    var w=this.getLeftWidth(), s=this.getLeftStyle(), d=this._defsX;

    d.borderLeft = this._generateDefString(w, s, this.getLeftColor());
    d.MozBorderLeftColors = this._generateMozColorDefString(w, s, "left");

    this._needsCompilationLeft = false;
  }

  qx.renderer.border.Border._resetBorderX = function(o)
  {
    var s = o._style;
    s.borderLeft = s.borderRight = s.MozBorderLeftColors = s.MozBorderRightColors = "";
  }

  qx.renderer.border.Border._resetBorderY = function(o)
  {
    var s = o._style;
    s.borderTop = s.borderBottom = s.MozBorderTopColors = s.MozBorderBottomColors = "";
  }
}
else
{
  qx.Proto._applyWidgetX = function(vObject)
  {
    this._applyWidgetXCommon(vObject);

    if (qx.renderer.border.Border.enhancedCrossBrowserMode)
    {
      if (this.getUseEnhancedCrossBrowserMode()) {
        vObject._createElementForEnhancedBorder();
      }

      if (vObject._borderStyle)
      {
        for (var i in this._enhancedDefsX) {
          vObject._borderStyle[i] = this._enhancedDefsX[i];
        }
      }
    }
  }

  qx.Proto._applyWidgetY = function(vObject)
  {
    this._applyWidgetYCommon(vObject);

    if (qx.renderer.border.Border.enhancedCrossBrowserMode)
    {
      if (this.getUseEnhancedCrossBrowserMode()) {
        vObject._createElementForEnhancedBorder();
      }

      if (vObject._borderStyle)
      {
        for (var i in this._enhancedDefsY) {
          vObject._borderStyle[i] = this._enhancedDefsY[i];
        }
      }
    }
  }

  qx.Proto._compileTop = function()
  {
    var vTopWidth = this.getTopWidth();
    var vTopStyle = this.getTopStyle();
    var vTopColor = this.getTopColor();

    switch(vTopWidth)
    {
      case 1:
        switch(vTopStyle)
        {
          case "outset":
          case "inset":
            vTopColor = (new qx.renderer.color.ColorObject(qx.renderer.border.Border.data[vTopWidth][vTopStyle]["top"][0]));
            vTopStyle = "solid";
        }

        break;

      case 2:
        switch(vTopStyle)
        {
          case "outset":
          case "inset":
          case "groove":
          case "ridge":
            if (qx.renderer.border.Border.enhancedCrossBrowserMode)
            {
              try
              {
                var c = qx.renderer.border.Border.data[vTopWidth][vTopStyle]["top"];

                if (typeof c === "object")
                {
                  vTopStyle = "solid";
                  vTopWidth = 1;
                  vTopColor = (new qx.renderer.color.ColorObject(c[1]));

                  this._enhancedDefsY.borderTop = this._generateDefString(vTopWidth, vTopStyle, vTopColor);

                  vTopColor = (new qx.renderer.color.ColorObject(c[0]));
                }
              }
              catch(ex)
              {
                this.error("Failed to compile top border", ex);
                this.warn("Details: Width=" + vTopWidth + ", Style=" + vTopStyle);
              }
            }
            else
            {
              vTopColor = (new qx.renderer.color.ColorObject("threedlightshadow"));
            }
        }

        break;
    }

    this._defsY.borderTop = this._generateDefString(vTopWidth, vTopStyle, vTopColor);
    this._needsCompilationTop = false;
  }

  qx.Proto._compileRight = function()
  {
    var vRightWidth = this.getRightWidth();
    var vRightStyle = this.getRightStyle();
    var vRightColor = this.getRightColor();

    switch(vRightWidth)
    {
      case 1:
        switch(vRightStyle)
        {
          case "outset":
          case "inset":
            vRightColor = (new qx.renderer.color.ColorObject(qx.renderer.border.Border.data[vRightWidth][vRightStyle]["right"][0]));
            vRightStyle = "solid";
        }

        break;

      case 2:
        switch(vRightStyle)
        {
          case "outset":
          case "inset":
          case "groove":
          case "ridge":
            if (qx.renderer.border.Border.enhancedCrossBrowserMode)
            {
              try
              {
                var c = qx.renderer.border.Border.data[vRightWidth][vRightStyle]["right"];

                if (typeof c === "object")
                {
                  vRightStyle = "solid";
                  vRightWidth = 1;
                  vRightColor = (new qx.renderer.color.ColorObject(c[1]));

                  this._enhancedDefsX.borderRight = this._generateDefString(vRightWidth, vRightStyle, vRightColor);

                  vRightColor = (new qx.renderer.color.ColorObject(c[0]));
                }
              }
              catch(ex)
              {
                this.error("Failed to compile right border", ex);
                this.warn("Details: Width=" + vRightWidth + ", Style=" + vRightStyle);
              }
            }
            else
            {
              vRightColor = (new qx.renderer.color.ColorObject("threedlightshadow"));
            }
        }

        break;
    }

    this._defsX.borderRight = this._generateDefString(vRightWidth, vRightStyle, vRightColor);
    this._needsCompilationRight = false;
  }

  qx.Proto._compileBottom = function()
  {
    var vBottomWidth = this.getBottomWidth();
    var vBottomStyle = this.getBottomStyle();
    var vBottomColor = this.getBottomColor();

    switch(vBottomWidth)
    {
      case 1:
        switch(vBottomStyle)
        {
          case "outset":
          case "inset":
            vBottomColor = (new qx.renderer.color.ColorObject(qx.renderer.border.Border.data[vBottomWidth][vBottomStyle]["bottom"][0]));
            vBottomStyle = "solid";
        }

        break;

      case 2:
        switch(vBottomStyle)
        {
          case "outset":
          case "inset":
          case "groove":
          case "ridge":
            if (qx.renderer.border.Border.enhancedCrossBrowserMode)
            {
              try
              {
                var c = qx.renderer.border.Border.data[vBottomWidth][vBottomStyle]["bottom"];

                if (typeof c === "object")
                {
                  vBottomStyle = "solid";
                  vBottomWidth = 1;
                  vBottomColor = (new qx.renderer.color.ColorObject(c[1]));

                  this._enhancedDefsY.borderBottom = this._generateDefString(vBottomWidth, vBottomStyle, vBottomColor);

                  vBottomColor = (new qx.renderer.color.ColorObject(c[0]));
                }
              }
              catch(ex) {
                this.error("Failed to compile bottom border", ex);
                this.warn("Details: Width=" + vBottomWidth + ", Style=" + vBottomStyle);
              }
            }
            else
            {
              vBottomColor = (new qx.renderer.color.ColorObject("threedlightshadow"));
            }
        }

        break;
    }

    this._defsY.borderBottom = this._generateDefString(vBottomWidth, vBottomStyle, vBottomColor);
    this._needsCompilationBottom = false;
  }

  qx.Proto._compileLeft = function()
  {
    var vLeftWidth = this.getLeftWidth();
    var vLeftStyle = this.getLeftStyle();
    var vLeftColor = this.getLeftColor();

    switch(vLeftWidth)
    {
      case 1:
        switch(vLeftStyle)
        {
          case "outset":
          case "inset":
            vLeftColor = (new qx.renderer.color.ColorObject(qx.renderer.border.Border.data[vLeftWidth][vLeftStyle]["left"][0]));
            vLeftStyle = "solid";
        }

        break;

      case 2:
        switch(vLeftStyle)
        {
          case "outset":
          case "inset":
          case "groove":
          case "ridge":
            if (qx.renderer.border.Border.enhancedCrossBrowserMode)
            {
              try
              {
                var c = qx.renderer.border.Border.data[vLeftWidth][vLeftStyle]["left"];

                if (typeof c === "object")
                {
                  vLeftStyle = "solid";
                  vLeftWidth = 1;
                  vLeftColor = (new qx.renderer.color.ColorObject(c[1]));

                  this._enhancedDefsX.borderLeft = this._generateDefString(vLeftWidth, vLeftStyle, vLeftColor);

                  vLeftColor = (new qx.renderer.color.ColorObject(c[0]));
                }
              }
              catch(ex) {
                this.error("Failed to compile left border", ex);
                this.warn("Details: Width=" + vLeftWidth + ", Style=" + vLeftStyle);
              }
            }
            else
            {
              vLeftColor = (new qx.renderer.color.ColorObject("threedlightshadow"));
            }
        }

        break;
    }

    this._defsX.borderLeft = this._generateDefString(vLeftWidth, vLeftStyle, vLeftColor);
    this._needsCompilationLeft = false;
  }

  qx.renderer.border.Border._resetBorderX = function(o)
  {
    var s = o._style;
    s.borderLeft = s.borderRight = "0px none";

    if (qx.renderer.border.Border.enhancedCrossBrowserMode)
    {
      s = o._borderStyle;
      if (s) {
        s.borderLeft = s.borderRight = "0px none";
      }
    }
  }

  qx.renderer.border.Border._resetBorderY = function(o)
  {
    var s = o._style;
    s.borderTop = s.borderBottom = "0px none";

    if (qx.renderer.border.Border.enhancedCrossBrowserMode)
    {
      s = o._borderStyle;
      if (s) {
        s.borderTop = s.borderBottom = "0px none";
      }
    }
  }
}











/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (typeof this._defsX === "object") {
    for (var i in this._defsX) {
      delete this._defsX[i];
    }
  }

  delete this._defsX;

  if (typeof this._defsY === "object") {
    for (var i in this._defsY) {
      delete this._defsY[i];
    }
  }

  delete this._defsY;

  if (qx.renderer.border.Border.enhancedCrossBrowserMode)
  {
    if (typeof this._enhancedDefsX === "object") {
      for (var i in this._enhancedDefsX) {
        delete this._enhancedDefsX[i];
      }
    }

    delete this._enhancedDefsX;

    if (typeof this._enhancedDefsY === "object") {
      for (var i in this._enhancedDefsY) {
        delete this._enhancedDefsY[i];
      }
    }

    delete this._enhancedDefsY;
  }

  delete this._themedEdges;

  return qx.core.Object.prototype.dispose.call(this);
}








/*
---------------------------------------------------------------------------
  PRESETS
---------------------------------------------------------------------------
*/

/*
qx.Class.presets =
{
  black : new qx.Class(1, "solid", "black"),
  white : new qx.Class(1, "solid", "white"),
  none : new qx.Class(0, "none")
}
*/
