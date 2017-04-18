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
var $ = document.querySelector.bind(document);

var perfChart = new Chart($("#perf-chart").getContext("2d")).Pie([]);

var signals = [
  "SIGHUP",
  "SIGINT",
  "SIGQUIT",
  "SIGILL",
  "SIGTRAP",
  "SIGABRT",
  "SIGEMT",
  "SIGFPE",
  "SIGKILL",
  "SIGBUS",
  "SIGSEGV"
];

/* i: float | 0 < i <= 1 */
function color(i) {
  if (i == 0) { i = 1; }

  return "rgb(128, " + (255 * i).toFixed(0) + "," + (255 * 1/i).toFixed(0) + ")";
}

var colors = [
  "#88a3f6", // solver
  "#1c4fee", // pin
  "#051547" // il_tool
];

function color_store() {
  var i = 0;

  return function next() {
    if (i >= colors.length) {
      return "black";
    }
    return colors[i++];
  }
}

var crashChart = new Chart(
  $("#crash-chart").getContext("2d"))
  .Pie(signals.map(function (signal, i, arr) {
    i = (i + 1) % arr.length;

    return {
      value: 1,
      label: signal,
      color: color(i/arr.length)
    }
  }));

$('#crash-legend').innerHTML = crashChart.generateLegend();

var coverageChart = new Chart(
  $("#coverage-chart").getContext("2d"))
  .Line({
    labels: [],
    datasets: [
      {
        label: "Block Coverage",
        fillColor: "rgba(220,220,220,0.2)",
        strokeColor: "rgba(220,220,220,1)",
        pointColor: "rgba(220,220,220,1)",
        pointStrokeColor: "#fff",
        pointHighlightFill: "#fff",
        pointHighlightStroke: "rgba(220,220,220,1)",
        data: []
      },
      {
        label: "Branch Coverage",
        fillColor: "rgba(151,187,205,0.2)",
        strokeColor: "rgba(151,187,205,1)",
        pointColor: "rgba(151,187,205,1)",
        pointStrokeColor: "#fff",
        pointHighlightFill: "#fff",
        pointHighlightStroke: "rgba(151,187,205,1)",
        data: []
      }
    ]
  }, {
    bezierCurve: false
  });

$('#coverage-legend').innerHTML = coverageChart.generateLegend();

coverageChart.addData([0, 0], "0s")

var visited_blocks = [0];
var taken_branches = [0];

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

function performance_legend(name) {
  var legend = document.createElement("div");

  var title = document.createElement("h2");
  var color = "#051547"; // il_tool legend
  if (name == "pin")
    color = "#1c4fee"; // pin legend
  if (name == "solver")
    color = "#88a3f6"; // solver legend
  title.style.color = color;

  title.innerText = display(name);
  legend.appendChild(title);

  var e = document.createElement("p");
  e.appendChild(new Text("Average: "));
  var average = document.createElement("span");
  e.appendChild(average);

  legend.appendChild(e);

  e = document.createElement("p");
  e.appendChild(new Text("Total: "));
  var total = document.createElement("span");
  e.appendChild(total);

  legend.appendChild(e);

  $("#perf-stats").appendChild(legend);

  return {
    set average(avg) {
      average.innerText = avg.toFixed(2) + 's';
    },

    set total(tot) {
      total.innerText = tot.toFixed(2) + 's';
    }
  }
}

function display(name) {
  return name.replace("_", " ").toUpperCase();
}

function assign(target, source) {
  for (var name in source) {
    target[name] = source[name];
  }
}

function delay(ms) {
  return function () {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  };
}

function update_stats() {
  json("/api/statistics.json")
  .then(update)
  .then(delay(3000))
  .then(ite(keep_updating, update_stats))
  .catch(stop_updating);
}

function each(fn, thing) {
  var i, n, keys;

  if (Array.isArray(thing) || typeof thing === "string") {
    for (i = 0, n = thing.length; i < n; i++) {
      fn(thing[i], i, thing);
    }
    return;
  }

  keys = Object.keys(thing);
  for (i = 0, n = keys.length; i < n; i++) {
    fn(thing[keys[i]], keys[i], thing);
  }
}

var nameToMeta = {};
var next_perf_color = color_store();

function update(data) {
  /* PERFORMANCE */
  var perf = data.performance;

  each(function update_perf_pie(data, name) {
    if (!(name in nameToMeta)) {
      perfChart.addData({
        value: 0,
        label: display(name),
        color: next_perf_color()
      });

      nameToMeta[name] = {
        segment: perfChart.segments[perfChart.segments.length - 1],
        legend: performance_legend(name)
      };
    }

    var meta = nameToMeta[name];
    meta.segment.value = data.total;
    assign(meta.legend, data);
  }, perf);

  perfChart.update();


  /* CRASHES */
  crashChart.segments.forEach(function (seg, i) {
    // Each segment value equals that of the number
    // of crashes with that crash signal.
    seg.value = data.crashes.filter(function (crash) {
      return crash.signal-1 == i;
    }).length;
  });

  crashChart.update();

  var cov = data.coverage;

  var current_data = coverageChart.datasets[0].points.length;

  if (current_data < cov.visited.blocks.length) {
    coverageChart.clear();

    // Blocks
    coverageChart.datasets[0].points.forEach(function (point, i) {
      point.value = visited_blocks[i]; // /cov.found.blocks * 100;
      point.x = coverageChart.scale.calculateX(i);
    });

    // Branches
    coverageChart.datasets[1].points.forEach(function (point, i) {
      point.value = taken_branches[i]; // /cov.found.branches * 100;
      point.x = coverageChart.scale.calculateX(i);
    });

    for (var i = current_data; i < cov.visited.blocks.length; i++) {
      coverageChart.addData([
        cov.visited.blocks[i], // /cov.found.blocks * 100,
        cov.visited.branches[i] ///cov.found.branches * 100
      ], cov.visited.timestamps[i].toFixed(2) + 's');

      visited_blocks.push(cov.visited.blocks[i]);
      taken_branches.push(cov.visited.branches[i]);
    }
  }

  if (data.done) {
    execution_complete();
    throw "done";
  }
}

function ite(cond, then, els) {
  return function () {
    return cond() ? then() : els && els();
  };
}

var should_update = true;

function keep_updating() {
  return should_update;
}

function execution_complete() {
  var top = $('.top-bar');
  top.style.background = '#90af60';
  resumeButton.remove();
}

var resumeButton = $('#resume-button');

function stop_updating(exc) {
  console.error(exc);
  resumeButton.innerText = "Resume";
  should_update = false;
}

resumeButton.addEventListener('click', function (event) {
  should_update = !should_update;

  if (should_update) {
    update_stats();
    event.target.innerText = "Stop";
  } else {
    event.target.innerText = "Resume";
  }
});

update_stats();
