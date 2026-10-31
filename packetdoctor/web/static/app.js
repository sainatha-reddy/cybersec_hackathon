/* Dashboard behaviour: upload, samples, downloads. Report drawing lives in report.js. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var current = null;

  function show(view) {
    $("upload-view").hidden = view !== "upload";
    $("loading").hidden = view !== "loading";
    $("report").hidden = view !== "report";
    $("report-actions").hidden = view !== "report";
  }

  function showError(msg) {
    show("upload");
    var e = $("error");
    e.textContent = msg;
    e.hidden = false;
  }

  async function request(url, body) {
    $("error").hidden = true;
    show("loading");
    try {
      var res = await fetch(url, { method: "POST", body: body });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.detail || ("Analysis failed (" + res.status + ")"));
      current = data;
      PacketDoctor.renderReport(data, $("report"));
      show("report");
      window.scrollTo(0, 0);
    } catch (err) {
      showError(err.message || String(err));
    }
  }

  function anonymizeForm() {
    var fd = new FormData();
    fd.append("anonymize", $("anonymize").checked ? "true" : "false");
    return fd;
  }

  function analyzeFile(file) {
    if (!file) return;
    var fd = anonymizeForm();
    fd.append("file", file, file.name);
    request("/api/analyze", fd);
  }

  function loadSamples() {
    fetch("/api/samples").then(function (r) { return r.json(); }).then(function (list) {
      var box = $("sample-list");
      var acronyms = { arp: "ARP", dns: "DNS", tcp: "TCP", ip: "IP", mtu: "MTU", dhcp: "DHCP" };
      list.sort(function (a, b) { return (b.name.indexOf("mixed") === 0) - (a.name.indexOf("mixed") === 0); });
      list.forEach(function (s) {
        var b = document.createElement("button");
        b.type = "button";
        b.className = "sample" + (s.name.indexOf("mixed") === 0 ? " featured" : "");
        var words = s.name.replace(/\.pcap(ng)?$/, "").split("_").map(function (w, i) {
          return acronyms[w] || (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w);
        });
        b.textContent = words.join(" ") + (/\.pcapng$/.test(s.name) ? " (pcapng)" : "");
        b.title = s.name + " (" + s.kb + " KB)";
        b.addEventListener("click", function () { request("/api/analyze-sample/" + encodeURIComponent(s.name), anonymizeForm()); });
        box.appendChild(b);
      });
    }).catch(function () {});
  }

  function download(name, blob) {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  function baseName() {
    var n = (current && current.capture.file_name) || "capture";
    return n.replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9._-]/g, "_") || "capture";
  }

  // standalone report: same renderer, inlined, data embedded as JSON
  async function downloadHtml() {
    if (!current) return;
    var res = await Promise.all([fetch("/static/style.css").then(function (r) { return r.text(); }), fetch("/static/report.js").then(function (r) { return r.text(); })]);
    var data = JSON.stringify(current).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
    var title = ("PacketDoctor report - " + current.capture.file_name).replace(/[<>&"]/g, "");
    var html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">" +
      "<title>" + title + "</title><style>" + res[0] + "</style></head><body class=\"standalone\">" +
      "<header class=\"topbar\"><div class=\"brand\"><span class=\"logo\">+</span><div><h1>PacketDoctor</h1><p class=\"tagline\">Offline network diagnosis report</p></div></div></header>" +
      "<main><section id=\"report\"></section></main>" +
      "<script type=\"application/json\" id=\"report-data\">" + data + "</script>" +
      "<script>" + res[1].replace(/<\//g, "<\\/") + "\nPacketDoctor.renderReport(JSON.parse(document.getElementById('report-data').textContent), document.getElementById('report'));</script>" +
      "</body></html>";
    download(baseName() + ".report.html", new Blob([html], { type: "text/html" }));
  }

  var dz = $("dropzone"), input = $("file-input");
  dz.addEventListener("click", function () { input.click(); });
  dz.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", function () { analyzeFile(input.files[0]); input.value = ""; });
  dz.addEventListener("dragover", function (e) { e.preventDefault(); dz.classList.add("over"); });
  dz.addEventListener("dragleave", function () { dz.classList.remove("over"); });
  dz.addEventListener("drop", function (e) { e.preventDefault(); dz.classList.remove("over"); analyzeFile(e.dataTransfer.files[0]); });
  $("new-analysis").addEventListener("click", function () { current = null; show("upload"); });
  $("download-json").addEventListener("click", function () {
    if (current) download(baseName() + ".report.json", new Blob([JSON.stringify(current, null, 2)], { type: "application/json" }));
  });
  $("download-html").addEventListener("click", downloadHtml);
  loadSamples();
})();
