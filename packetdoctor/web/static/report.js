/* PacketDoctor report renderer.
 *
 * Used by the dashboard and embedded in standalone HTML reports. Every piece
 * of text from the capture is inserted with textContent / createTextNode,
 * never innerHTML, so hostile strings (e.g. DNS names) cannot inject markup.
 */
(function (global) {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var VERDICT_TEXT = {
    ATTACK: "an attack",
    FAULT: "a fault, not an attack",
    UNCERTAIN: "uncertain, needs a human look"
  };

  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else node.setAttribute(k, v === true ? "" : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(node, c); }); return; }
    node.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
  }

  function svg(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, String(attrs[k])); });
    return node;
  }

  function fmtTime(s) {
    if (s === null || s === undefined) return "?";
    if (s < 120) return s.toFixed(1) + " s";
    var m = Math.floor(s / 60);
    return m + " min " + Math.round(s - m * 60) + " s";
  }

  function fmtBytes(b) {
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    return (b / 1048576).toFixed(1) + " MB";
  }

  function verdictBadge(v) {
    return el("span", { class: "badge badge-" + v.toLowerCase(), text: v });
  }

  function severityDots(sev) {
    var wrap = el("span", { class: "sev", title: "Severity " + sev + " of 5", "aria-label": "Severity " + sev + " of 5" });
    for (var i = 1; i <= 5; i++) wrap.appendChild(el("span", { class: i <= sev ? "dot on" : "dot" }));
    return wrap;
  }

  /* ---- header: health gauge + summary -------------------------------- */

  function gauge(score, grade) {
    var r = 52, c = 2 * Math.PI * r;
    var s = svg("svg", { viewBox: "0 0 120 120", class: "gauge", role: "img", "aria-label": "Network health " + score + " out of 100" });
    s.appendChild(svg("circle", { cx: 60, cy: 60, r: r, class: "gauge-bg" }));
    var arc = svg("circle", {
      cx: 60, cy: 60, r: r, class: "gauge-fg grade-" + grade.toLowerCase().replace(/\s+/g, "-"),
      "stroke-dasharray": c.toFixed(1), "stroke-dashoffset": (c * (1 - score / 100)).toFixed(1),
      transform: "rotate(-90 60 60)"
    });
    s.appendChild(arc);
    var t = svg("text", { x: 60, y: 58, class: "gauge-score", "text-anchor": "middle" });
    t.textContent = String(score);
    s.appendChild(t);
    var t2 = svg("text", { x: 60, y: 78, class: "gauge-label", "text-anchor": "middle" });
    t2.textContent = "/ 100";
    s.appendChild(t2);
    return s;
  }

  function header(report) {
    var cap = report.capture, h = report.health, sm = report.summary, net = report.network;
    var stats = el("div", { class: "stat-row" },
      stat(sm.attacks, sm.attacks === 1 ? "attack" : "attacks", "attack"),
      stat(sm.faults, sm.faults === 1 ? "fault" : "faults", "fault"),
      stat(sm.uncertain, "uncertain", "uncertain")
    );
    var meta = el("dl", { class: "meta" },
      metaItem("Capture", cap.file_name || "capture"),
      metaItem("Packets", cap.packets.toLocaleString() + " (" + fmtBytes(cap.bytes) + ", " + cap.format + ")"),
      metaItem("Duration", fmtTime(cap.duration_s)),
      metaItem("Gateway", net.gateway_ip ? net.gateway_ip + (net.gateway_mac ? " (" + net.gateway_mac + ")" : "") : "not identified"),
      metaItem("Conversations", net.flows + " TCP, " + net.dns_queries + " DNS lookups")
    );
    var warnings = (cap.warnings || []).concat(report.detector_errors || []).map(function (w) {
      return el("p", { class: "warning", text: w });
    });
    if (report.anonymized) warnings.push(el("p", { class: "note", text: "Addresses in this report are anonymised." }));
    return el("section", { class: "card summary" },
      el("div", { class: "gauge-wrap" }, gauge(h.score, h.grade), el("p", { class: "grade grade-text-" + h.grade.toLowerCase().replace(/\s+/g, "-"), text: h.grade })),
      el("div", { class: "summary-body" },
        el("h2", { text: "Diagnosis" }),
        el("p", { class: "lead", text: h.summary }),
        stats, meta, warnings
      )
    );
  }

  function stat(n, label, kind) {
    return el("div", { class: "stat stat-" + kind + (n ? "" : " zero") }, el("span", { class: "stat-n", text: n }), el("span", { class: "stat-l", text: label }));
  }

  function metaItem(k, v) {
    return [el("dt", { text: k }), el("dd", { text: v })];
  }

  /* ---- timeline -------------------------------------------------------- */

  function timeline(report) {
    var tl = report.timeline, series = tl.series || [], events = tl.events || [];
    var duration = Math.max(report.capture.duration_s || 0, series.length ? series[series.length - 1].t + tl.bucket_s : 1, 1);
    var W = 1000, left = 8, right = 8, chartH = 70, rowH = 22, top = 10;
    var rowsTop = top + chartH + 18;
    var H = rowsTop + Math.max(1, events.length) * rowH + 24;
    var x = function (t) { return left + (W - left - right) * Math.max(0, Math.min(1, t / duration)); };
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, class: "timeline", role: "img", "aria-label": "Traffic and incidents over time" });

    var max = 1;
    series.forEach(function (p) { if (p.packets > max) max = p.packets; });
    if (series.length) {
      var d = "M " + x(series[0].t) + " " + (top + chartH);
      series.forEach(function (p) { d += " L " + x(p.t).toFixed(1) + " " + (top + chartH - (p.packets / max) * chartH).toFixed(1); });
      d += " L " + x(series[series.length - 1].t) + " " + (top + chartH) + " Z";
      s.appendChild(svg("path", { d: d, class: "traffic" }));
    }
    var lbl = svg("text", { x: left + 4, y: top + 12, class: "axis-label" });
    lbl.textContent = "traffic (packets per " + tl.bucket_s + " s, peak " + max + ")";
    s.appendChild(lbl);

    events.forEach(function (ev, i) {
      var y = rowsTop + i * rowH;
      var g = svg("g", { class: "band band-" + ev.verdict.toLowerCase(), tabindex: 0, "data-target": ev.id });
      var x0 = x(ev.start), x1 = Math.max(x(ev.end), x0 + 6);
      g.appendChild(svg("rect", { x: x0, y: y, width: x1 - x0, height: rowH - 6, rx: 3 }));
      var shade = svg("rect", { x: x0, y: top, width: x1 - x0, height: chartH, class: "shade" });
      s.insertBefore(shade, s.firstChild);
      var t = svg("text", { x: x1 + 6 > W - 220 ? x0 - 6 : x1 + 6, y: y + rowH - 10, class: "band-label", "text-anchor": x1 + 6 > W - 220 ? "end" : "start" });
      t.textContent = ev.id + " " + ev.label;
      g.appendChild(t);
      var title = svg("title", {});
      title.textContent = ev.id + " " + ev.verdict + ": " + ev.label + " (" + fmtTime(ev.start) + " to " + fmtTime(ev.end) + ")";
      g.appendChild(title);
      g.addEventListener("click", function () { focusIncident(ev.id); });
      g.addEventListener("keydown", function (e) { if (e.key === "Enter") focusIncident(ev.id); });
      s.appendChild(g);
    });

    var step = niceStep(duration);
    for (var t = 0; t <= duration + 1e-9; t += step) {
      s.appendChild(svg("line", { x1: x(t), x2: x(t), y1: top + chartH, y2: top + chartH + 4, class: "tick" }));
      var anchor = t === 0 ? "start" : (t + step > duration + 1e-9 && x(t) > W - 40 ? "end" : "middle");
      var tt = svg("text", { x: x(t), y: H - 6, class: "axis-label", "text-anchor": anchor });
      tt.textContent = fmtTime(t);
      s.appendChild(tt);
    }
    return el("section", { class: "card" },
      el("h2", { text: "Timeline" }),
      el("p", { class: "muted", text: "Traffic volume with each problem's time span. Click a bar to jump to its explanation." }),
      el("div", { class: "timeline-wrap" }, s)
    );
  }

  function niceStep(duration) {
    var raw = duration / 8, steps = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600];
    for (var i = 0; i < steps.length; i++) if (steps[i] >= raw) return steps[i];
    return Math.ceil(raw / 3600) * 3600;
  }

  function focusIncident(id) {
    var card = document.getElementById("incident-" + id);
    if (!card) return;
    card.scrollIntoView({ behavior: "smooth", block: "start" });
    card.classList.add("flash");
    setTimeout(function () { card.classList.remove("flash"); }, 1200);
  }

  /* ---- incidents --------------------------------------------------------- */

  function meter(label, value, kind) {
    var bar = el("span", { class: "meter-fill meter-" + kind });
    bar.style.width = Math.round(value * 100) + "%";
    return el("div", { class: "meter" },
      el("span", { class: "meter-label", text: label }),
      el("span", { class: "meter-track" }, bar),
      el("span", { class: "meter-value", text: Math.round(value * 100) + "%" })
    );
  }

  function evidenceTable(inc, evidence) {
    var rows = inc.packet_ids.map(function (id) { return evidence[String(id)]; }).filter(Boolean);
    if (!rows.length) return null;
    var tbody = el("tbody");
    rows.forEach(function (r) {
      tbody.appendChild(el("tr", null,
        el("td", { class: "num", text: r.no }),
        el("td", { class: "num", text: r.time.toFixed(3) }),
        el("td", { text: r.src }),
        el("td", { text: r.dst }),
        el("td", { text: r.proto }),
        el("td", { class: "info", text: r.info })
      ));
    });
    return el("details", { class: "evidence" },
      el("summary", { text: "Evidence: " + rows.length + " packets (numbers match Wireshark's No. column)" }),
      el("div", { class: "table-wrap" },
        el("table", null,
          el("thead", null, el("tr", null, ["No.", "Time (s)", "Source", "Destination", "Proto", "Info"].map(function (h) { return el("th", { text: h }); }))),
          tbody
        )
      )
    );
  }

  function chain(inc) {
    if (!inc.consequences.length) return null;
    var wrap = el("div", { class: "chain" });
    wrap.appendChild(el("div", { class: "chain-node chain-root chain-" + inc.verdict.toLowerCase() }, el("strong", { text: inc.label }), el("span", { text: fmtTime(inc.rel_start) })));
    inc.consequences.forEach(function (c) {
      wrap.appendChild(el("div", { class: "chain-arrow", "aria-hidden": "true", text: "→" }));
      wrap.appendChild(el("div", { class: "chain-node", title: c.what },
        el("strong", { text: c.label }),
        el("span", { text: c.title }),
        el("em", { text: c.reason })
      ));
    });
    return el("div", { class: "block" }, el("h4", { text: "Knock-on effects (caused by this problem, not separate problems)" }), wrap);
  }

  function copyRow(label, value) {
    var code = el("code", { text: value });
    var btn = el("button", { type: "button", class: "copy", text: "Copy" });
    btn.addEventListener("click", function () {
      var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy"; }, 1200); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(value).then(done, function () {});
    });
    return el("div", { class: "ws-row" }, el("span", { class: "ws-label", text: label }), code, btn);
  }

  function wiresharkBox(inc) {
    if (!inc.wireshark_filter && !inc.wireshark_exact) return null;
    return el("div", { class: "block ws" },
      el("h4", { text: "Dig deeper in Wireshark (paste into the display filter bar)" }),
      inc.wireshark_filter ? copyRow("Pattern", inc.wireshark_filter) : null,
      inc.wireshark_exact ? copyRow("Exact packets", inc.wireshark_exact) : null
    );
  }

  function incidentCard(inc, evidence) {
    var ex = inc.explanation;
    var forAttack = inc.evidence_for_attack.map(function (e) { return el("li", { class: "ev-attack", text: e.text }); });
    var forFault = inc.evidence_for_fault.map(function (e) { return el("li", { class: "ev-fault", text: e.text }); });
    var notes = inc.notes.map(function (n) { return el("li", { class: "ev-note", text: n }); });
    return el("article", { class: "card incident incident-" + inc.verdict.toLowerCase(), id: "incident-" + inc.id, "data-verdict": inc.verdict },
      el("div", { class: "incident-head" },
        el("span", { class: "inc-id", text: inc.id }),
        verdictBadge(inc.verdict),
        el("span", { class: "inc-label", text: inc.label }),
        severityDots(inc.severity),
        el("span", { class: "inc-time", text: fmtTime(inc.rel_start) + " – " + fmtTime(inc.rel_end) })
      ),
      el("h3", { text: inc.title }),
      el("div", { class: "block" }, el("h4", { text: "What happened" }), el("p", { text: ex.what })),
      ex.why ? el("p", { class: "why" }, el("strong", { text: "Why it matters: " }), ex.why) : null,
      el("div", { class: "block verdict-box" },
        el("h4", null, "Why we think this is " + VERDICT_TEXT[inc.verdict], el("span", { class: "conf", text: " confidence " + Math.round(inc.confidence * 100) + "%" })),
        el("div", { class: "meters" }, meter("Attack clues", inc.attack_score, "attack"), meter("Fault clues", inc.benign_score, "fault")),
        el("ul", { class: "evlist" }, forAttack, forFault, notes)
      ),
      inc.related.length ? el("p", { class: "muted" }, el("strong", { text: "Also seen as: " }), inc.related.map(function (r) { return r.title; }).join("; ")) : null,
      chain(inc),
      el("div", { class: "two-col" },
        el("div", { class: "block" }, el("h4", { text: "Likely cause" }), el("p", { text: ex.cause })),
        el("div", { class: "block fix" }, el("h4", { text: "What to do" }), el("ol", null, ex.fixes.map(function (f) { return el("li", { text: f }); })))
      ),
      evidenceTable(inc, evidence),
      wiresharkBox(inc),
      ex.technical ? el("p", { class: "technical", text: "Technical: " + ex.technical }) : null
    );
  }

  function filters(container, report) {
    var bar = el("div", { class: "filters", role: "toolbar", "aria-label": "Filter incidents" });
    var opts = [["ALL", "All (" + report.incidents.length + ")"], ["ATTACK", "Attacks (" + report.summary.attacks + ")"], ["FAULT", "Faults (" + report.summary.faults + ")"], ["UNCERTAIN", "Uncertain (" + report.summary.uncertain + ")"]];
    opts.forEach(function (o, i) {
      var b = el("button", { type: "button", class: i === 0 ? "chip active" : "chip", text: o[1] });
      b.addEventListener("click", function () {
        Array.prototype.forEach.call(bar.children, function (c) { c.classList.remove("active"); });
        b.classList.add("active");
        Array.prototype.forEach.call(container.querySelectorAll(".incident"), function (card) {
          card.hidden = !(o[0] === "ALL" || card.getAttribute("data-verdict") === o[0]);
        });
      });
      bar.appendChild(b);
    });
    return bar;
  }

  function networkCard(report) {
    var hosts = report.network.hosts || [];
    var protos = report.protocols || {};
    var total = 0;
    Object.keys(protos).forEach(function (k) { total += protos[k]; });
    var bars = Object.keys(protos).map(function (k) {
      var fill = el("span", { class: "pbar-fill" });
      fill.style.width = (100 * protos[k] / Math.max(1, total)).toFixed(1) + "%";
      return el("div", { class: "pbar" }, el("span", { class: "pbar-label", text: k }), el("span", { class: "pbar-track" }, fill), el("span", { class: "pbar-n", text: protos[k] }));
    });
    var tbody = el("tbody");
    hosts.slice(0, 50).forEach(function (h) {
      tbody.appendChild(el("tr", { class: h.macs.length > 1 ? "warn-row" : null },
        el("td", { text: h.ip + (h.ip === report.network.gateway_ip ? " (gateway)" : "") }),
        el("td", { text: h.macs.join(", ") }),
        el("td", { class: "num", text: h.packets })
      ));
    });
    return el("section", { class: "card" },
      el("h2", { text: "Network overview" }),
      el("div", { class: "two-col" },
        el("div", null, el("h4", { text: "Protocols" }), bars),
        el("div", null, el("h4", { text: "Local devices seen" }),
          el("div", { class: "table-wrap" }, el("table", null,
            el("thead", null, el("tr", null, el("th", { text: "IP" }), el("th", { text: "Hardware address(es)" }), el("th", { text: "Packets" }))),
            tbody)))
      )
    );
  }

  function renderReport(report, container) {
    while (container.firstChild) container.removeChild(container.firstChild);
    container.appendChild(header(report));
    container.appendChild(timeline(report));
    if (report.incidents.length) {
      var list = el("section", { class: "incidents" });
      list.appendChild(el("div", { class: "incidents-head" }, el("h2", { text: "Problems found" }), filters(list, report)));
      report.incidents.forEach(function (inc) { list.appendChild(incidentCard(inc, report.evidence || {})); });
      container.appendChild(list);
    } else {
      container.appendChild(el("section", { class: "card ok" }, el("h2", { text: "No problems found" }), el("p", { text: "No faults or attacks were detected in this capture." })));
    }
    container.appendChild(networkCard(report));
    container.appendChild(el("p", { class: "muted small", text: "Generated by " + report.tool.name + " " + report.tool.version + " on " + report.analysed_at + "." }));
  }

  global.PacketDoctor = { renderReport: renderReport };
})(window);
