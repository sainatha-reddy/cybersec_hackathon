/* Dashboard behaviour: upload, samples, downloads. Report drawing lives in report.js. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var current = null;
  var controller = null;
  var activeJob = null;
  var uploadLimit = null;

  function show(view) {
    $("upload-view").hidden = view !== "upload";
    $("loading").hidden = view !== "loading";
    $("report").hidden = view !== "report";
    $("report-actions").hidden = view !== "report";
    $("main").setAttribute("aria-busy", view === "loading" ? "true" : "false");
    if (view === "loading") $("loading-title").focus();
    if (view === "upload") $("dropzone").focus();
  }

  function showError(msg) {
    show("upload");
    var e = $("error");
    e.textContent = msg;
    e.hidden = false;
    e.focus();
    $("status").textContent = msg;
  }

  async function request(url, body) {
    if (controller) return;
    controller = new AbortController();
    var requestController = controller;
    $("error").hidden = true;
    $("progress").textContent = "Uploading and preparing analysis…";
    $("status").textContent = "Analysis started.";
    show("loading");
    try {
      var res = await fetch(url + "?background=true", { method: "POST", body: body, signal: requestController.signal });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.detail || ("Analysis failed (" + res.status + ")"));
      activeJob = data.job_id;
      while (data.job_id || data.status === "running") {
        await new Promise(function (resolve) { setTimeout(resolve, 300); });
        var progressResponse = await fetch("/api/jobs/" + activeJob, { signal: requestController.signal });
        data = await progressResponse.json();
        if (!progressResponse.ok) throw new Error(data.detail || "Could not read analysis status.");
        $("progress").textContent = "Examining packets · " + data.elapsed_s + " seconds elapsed";
        if (data.status === "failed" || data.status === "cancelled") throw new Error(data.error || "Analysis cancelled.");
        if (data.status === "complete") { data = data.report; break; }
      }
      current = data;
      PacketDoctor.renderReport(data, $("report"));
      show("report");
      window.scrollTo(0, 0);
      $("diagnosis-title").focus({ preventScroll: true });
      $("status").textContent = data.health.summary;
    } catch (err) {
      if (err.name === "AbortError") { show("upload"); $("status").textContent = "Analysis cancelled."; }
      else showError(err.message || String(err));
    } finally {
      if (activeJob) fetch("/api/jobs/" + activeJob, { method: "DELETE" }).catch(function () {});
      activeJob = null;
      controller = null;
    }
  }

  function anonymizeForm() {
    var fd = new FormData();
    fd.append("anonymize", $("anonymize").checked ? "true" : "false");
    return fd;
  }

  function analyzeFile(file) {
    if (!file) return;
    if (uploadLimit && file.size > uploadLimit) { showError("File exceeds the displayed upload limit. Choose a smaller capture."); return; }
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
    }).catch(function () { $("sample-list").textContent = "Samples could not be loaded. Refresh the page or upload your own capture."; });
    fetch("/api/health").then(function (response) { return response.json(); }).then(function (limits) {
      uploadLimit = limits.max_upload_mb * 1024 * 1024;
      $("limits").textContent = "Upload limit: " + limits.max_upload_mb + " MB · Time limit: " + limits.timeout_seconds + " seconds · Memory budget: " + limits.max_memory_mb + " MB";
    }).catch(function () { $("limits").textContent = "Analysis limits are unavailable. Check that the local server is running."; });
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
  $("download-html").addEventListener("click", function () {
    var button = $("download-html");
    button.disabled = true;
    downloadHtml().catch(function () {
      $("status").textContent = "The report could not be downloaded. Check the local server and try again.";
    }).finally(function () { button.disabled = false; });
  });
  $("cancel-analysis").addEventListener("click", function () {
    if (activeJob) fetch("/api/jobs/" + activeJob, { method: "DELETE" }).catch(function () {});
    if (controller) controller.abort();
  });
  loadSamples();
})();
