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

#module(dev)

************************************************************************ */

qx.OO.defineClass("qx.dev.TimeTracker", qx.core.Object,
function()
{
  qx.core.Object.call(this);

  this._functions = qx.lang.Array.fromArguments(arguments);

  this.buttonSets();
});

qx.dev.TimeTracker.compare = function(a, b) {
  return a-b;
}






/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.buttonSets = function()
{
  var btnLayout = new qx.ui.layout.HorizontalBoxLayout;

  btnLayout.setLocation(20, 48);
  btnLayout.setSpacing(5);

  var loopLabel = new qx.ui.basic.Atom("Method Loops: ");
  loopLabel.setAllowStretchY(false);
  loopLabel.setVerticalAlign("middle");

  var loopInput = new qx.ui.form.TextField("100");
  loopInput.setAllowStretchY(false);
  loopInput.setWidth(50);
  loopInput.setVerticalAlign("middle");

  var repeatLabel = new qx.ui.basic.Atom("Repeat Number: ");
  repeatLabel.setAllowStretchY(false);
  repeatLabel.setVerticalAlign("middle");
  repeatLabel.setMarginLeft(30);

  var btnStart1 = new qx.ui.form.Button("Start 3x", "icon/16/button-ok.png");
  var btnStart2 = new qx.ui.form.Button("Start 7x", "icon/16/button-ok.png");
  var btnStart3 = new qx.ui.form.Button("Start 15x", "icon/16/button-ok.png");
  var btnStart4 = new qx.ui.form.Button("Start 25x", "icon/16/button-ok.png");

  btnStart1.addEventListener("execute", function() { this.start(3, parseInt(loopInput.getValue())); }, this);
  btnStart2.addEventListener("execute", function() { this.start(7, parseInt(loopInput.getValue())); }, this);
  btnStart3.addEventListener("execute", function() { this.start(15, parseInt(loopInput.getValue())); }, this);
  btnStart4.addEventListener("execute", function() { this.start(25, parseInt(loopInput.getValue())); }, this);

  var htmlOutput = this._output = new qx.ui.embed.HtmlEmbed();

  htmlOutput.setHtml("");
  htmlOutput.setLocation(20, 78);
  htmlOutput.setRight(335);
  htmlOutput.setBottom(48);
  htmlOutput.setBorder("1px solid black");
  htmlOutput.setBackgroundColor("white");
  htmlOutput.setPadding(10);
  htmlOutput.setOverflow("auto");
  htmlOutput.addToDocument();

  btnLayout.add(loopLabel, loopInput, repeatLabel, btnStart1, btnStart2, btnStart3, btnStart4);
  btnLayout.addToDocument();
}

qx.Proto.start = function(vRounds, vLoops)
{
  var vFuncs = this._functions;
  var vLength = vFuncs.length;
  var vStart;
  var vLocalTimes;
  var vAllTimes = [];
  var vHtmlMeasured = [];
  var vHtmlResults = [];
  var vCellWidth = Math.round(100 / (vLength+1)) + "%";

  vHtmlMeasured.push("<h3>Measured Values</h3>");

  vHtmlMeasured.push("<style type='text/css'>.output{border: 1px solid black; width:100%; margin-bottom: 20px } .output thead{ font-weight: bold; } .output td, .output th{ text-align:left; width: " + vCellWidth + "; } .output td{padding:4px}</style>");

  vHtmlMeasured.push("<table class='output'>");

  vHtmlMeasured.push("<thead>");

  vHtmlMeasured.push("<tr><td>&#160;</td>");

  for (var j=0; j<vLength; j++) {
    vHtmlMeasured.push("<td>Method " + (j+1) + "</td>");
  }

  vHtmlMeasured.push("</thead><tbody>");

  for (var i=0; i<vRounds; i++)
  {
    vLocalTimes = [];

    for (var j=0; j<vLength; j++)
    {
      vStart = (new Date).valueOf();

      vFuncs[j](vLoops);

      vLocalTimes.push((new Date).valueOf()-vStart);
    }

    vHtmlMeasured.push("<tr><th>Round " + i + "</th>");

    for (var j=0; j<vLocalTimes.length; j++) {
      vHtmlMeasured.push("<td>" + vLocalTimes[j] + "</td>");
    }

    vHtmlMeasured.push("</tr>");
    vAllTimes.push(vLocalTimes);
  }

  vHtmlMeasured.push("</tbody></table>");





  var vSum, vMeanValue, vMeanAll=[], vMeanMin=1e7, vMeanMax=0;

  for (var j=0; j<vLength; j++)
  {
    vSum = 0;

    for (var i=0; i<vRounds; i++)
    {
      vSum += vAllTimes[i][j];
    }

    vMeanValue = Math.round(vSum / vRounds);

    vMeanAll.push(vMeanValue);

    vMeanMin = Math.min(vMeanMin, vMeanValue);
    vMeanMax = Math.max(vMeanMax, vMeanValue);
  }



  var vMedian, vMedianValue, vMedianAll=[], vMedianMin=1e7, vMedianMax=0;

  for (var j=0; j<vLength; j++)
  {
    vMedian = [];

    for (var i=0; i<vRounds; i++)
    {
      vMedian.push(vAllTimes[i][j]);
    }

    vMedian.sort(qx.dev.TimeTracker.compare);
    vMedianValue = vMedian[Math.floor(vRounds / 2)].toString();

    vMedianAll.push(vMedianValue);

    vMedianMin = Math.min(vMedianValue, vMedianMin);
    vMedianMax = Math.max(vMedianValue, vMedianMax);
  }





  vHtmlResults.push("<h3>Results Summary</h3>");

  vHtmlResults.push("<table class='output'>");

  vHtmlResults.push("<thead>");

  vHtmlResults.push("<tr><td>&#160;</td>");

  for (var j=0; j<vLength; j++) {
    vHtmlResults.push("<td>Method " + (j+1) + "</td>");
  }

  vHtmlResults.push("</thead><tbody>");


  vHtmlResults.push("<tr>");

  vHtmlResults.push("<th>Median</th>");

  for (var j=0; j<vLength; j++) {
    vHtmlResults.push("<td>" + vMedianAll[j] + "</td>");
  }

  vHtmlResults.push("</tr>");



  vHtmlResults.push("<tr>");

  vHtmlResults.push("<th>Median Factor</th>");

  for (var j=0; j<vLength; j++)
  {
    vHtmlResults.push("<td>");
    vHtmlResults.push(vMedianMin > 0 ? Math.round(vMedianAll[j] / vMedianMin) : "1");
    vHtmlResults.push("x</td>");
  }

  vHtmlResults.push("</tr>");



  vHtmlResults.push("<tr>");

  vHtmlResults.push("<th>Mean</th>");

  for (var j=0; j<vLength; j++) {
    vHtmlResults.push("<td>" + vMeanAll[j] + "</td>");
  }

  vHtmlResults.push("</tr>");



  vHtmlResults.push("<tr>");

  vHtmlResults.push("<th>Mean Factor</th>");

  for (var j=0; j<vLength; j++)
  {
    vHtmlResults.push("<td>");
    vHtmlResults.push(vMeanMin > 0 ? Math.round(vMeanAll[j] / vMeanMin) : 1);
    vHtmlResults.push("x</td>");
  }

  vHtmlResults.push("</tr>");



  vHtmlResults.push("<tr>");

  vHtmlResults.push("<th>Winner</th>");

  for (var j=0; j<vLength; j++)
  {
    vHtmlResults.push("<td>");

    if (vMedianMin == vMedianAll[j] && vMeanMin == vMeanAll[j])
    {
      vHtmlResults.push("BOTH");
    }

    else if (vMedianMin == vMedianAll[j])
    {
      vHtmlResults.push("MEDIAN");
    }

    else if (vMeanMin == vMeanAll[j])
    {
      vHtmlResults.push("MEAN");
    }

    vHtmlResults.push("</td>");
  }

  vHtmlResults.push("</tr>");

  vHtmlResults.push("</tbody></table>");

  this._output.setHtml(vHtmlResults.join("") + vHtmlMeasured.join(""));
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

  this._functions = null;

  return qx.core.Object.prototype.dispose.call(this);
}
