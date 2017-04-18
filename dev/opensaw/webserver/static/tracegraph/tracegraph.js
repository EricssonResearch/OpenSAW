/*
    Open Security Analysis Workbench (OpenSAW) - A concolic security test tool
    Copyright (C) 2016 Ericsson AB

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

// Drawing helpers
var width = 900, height = 900;

//var color = d3.scale.category20c();
var color = d3.scale.linear().domain([0, 150]).range(["#0000ff", "#00ff00"]);

var nodeMap = [];
var nodes = []; 
var links = [];

var force = d3.layout.force()
    .nodes(nodes)
    .links(links)
    .charge(-30)
    .linkDistance(20)
    .size([width, height])
    .on("tick", tick);

var svg = d3.select("#graph").append("svg")
    .attr("width", width)
    .attr("height", height);

var link = svg.selectAll(".link");

var node = svg.selectAll(".node");

function update_data(tracegraph) {
    tracegraph.nodes.forEach(function(n, index, arr) {
	if (nodeMap[n.id] == undefined) {
	    nodeMap[n.id] = n;
	    nodes.push(n);
	}
    });
    links.length = 0;
    tracegraph.links.forEach(function(l, index, arr) {
	links.push({"source": nodeMap[l.source], 
		    "target": nodeMap[l.target],
		    "value":  l.value})
    });
}

function draw_graph(tracegraph) {
    update_data(tracegraph);
    link = link.data(force.links());
    link.enter().append("line")
	.attr("class", "link")
	.style("stroke-width", function(d) { return Math.sqrt(d.value); });
    link.exit().remove();

    node = node.data(force.nodes());
    node.enter().append("circle")
	.attr("class", "node")
	.attr("r", function(d) {
	    if (d.id == "100000000_0") {
		return 10;
		}
	    else {
		return 5;
	    }})
	.style("fill", function(d) { return color(d.group); });
    node.exit().remove();

    node.append("title").text(function(d) { return d.id; });

    force.start();
}

function tick() {
    node.attr("cx", function(d) { return d.x; })
	.attr("cy", function(d) { return d.y; });

    link.attr("x1", function(d) { return d.source.x; })
	.attr("y1", function(d) { return d.source.y; })
	.attr("x2", function(d) { return d.target.x; })
	.attr("y2", function(d) { return d.target.y; });
}

// Request
function get(url) {
  return new Promise(function (res, rej) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url)
    xhr.onload = function () { res(xhr.responseText); };
    xhr.onerror = rej;
    xhr.send();
  });
}

function json(url) {
    return get(url).then(JSON.parse);
}

function delay(ms) {
  return function () {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  };
}

// Progress helpers
var shouldUpdate = true;

function keep_updating() {
  return shouldUpdate;
}

var resumeButton = document.getElementById('resumeButton');

function stop_updating() {
  resumeButton.innerText = "Resume";
  shouldUpdate = false;
}

resumeButton.addEventListener('click', function (event) {
  shouldUpdate = !shouldUpdate;

  if (shouldUpdate) {
    update();
    event.target.innerText = "Stop";
  } else {
    event.target.innerText = "Resume";
  }
});

function update_tracegraph() {
    json("/api/tracegraph.json")
	.then(draw_graph).then(delay(2000)).then(update_tracegraph);
}

update_tracegraph();
