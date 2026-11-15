// Shared frontend helpers used by every page

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Calls the backend. Returns parsed JSON, or throws an Error with the server's message.
async function api(method, url, body) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (HTTP ${res.status})`);
  return data;
}

function showError(el, message) {
  el.innerHTML = `<div class="msg">${esc(message)}</div>`;
}

// Adds an "Upload file" button above a text box. The chosen file's text fills the box.
// accept: allowed file types. transform (optional): changes the text before it is shown.
function addUploadButton(targetId, accept, hint, transform) {
  const target = document.getElementById(targetId);
  const wrap = document.createElement("div");
  wrap.className = "row";
  wrap.style.marginBottom = "8px";
  wrap.innerHTML = `
    <label class="small" style="padding:8px 12px;cursor:pointer">Upload file
      <input type="file" accept="${accept}" style="display:none">
    </label>
    <span class="how status" style="margin:0">${hint}</span>`;
  target.parentNode.insertBefore(wrap, target);

  const input = wrap.querySelector("input");
  const status = wrap.querySelector(".status");
  input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;
    // Vercel Functions accept request bodies up to 4.5 MB. Leave headroom for
    // multipart form data and the later JSON request sent by the scanner.
    const maxUploadBytes = 4 * 1024 * 1024;
    if (file.size > maxUploadBytes) {
      status.textContent = `“${file.name}” is ${(file.size / 1024 / 1024).toFixed(1)} MB. Use a file under 4 MB or split the log into smaller files before scanning.`;
      input.value = "";
      return;
    }
    status.textContent = "Reading " + file.name + " ...";
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/extract", { method: "POST", body: form });
      const raw = await res.text();
      let data;
      try { data = JSON.parse(raw); }
      catch {
        if (res.status === 413) throw new Error("The uploaded file is too large for the deployed server. Use a file under 4 MB or split the log into smaller files.");
        throw new Error(`Upload failed (HTTP ${res.status}). Please try a smaller file.`);
      }
      if (!res.ok) throw new Error(data.error || `Upload failed (HTTP ${res.status})`);
      target.value = transform ? transform(data.text) : data.text;
      status.textContent = `Loaded ${data.name} (${data.method}). Check the text, then run it.`;
    } catch (e) {
      status.textContent = e.message;
    }
    input.value = "";
  });
}

// Motion is Framer's lightweight, framework-agnostic animation library. Loading it
// progressively keeps the tools fully usable if a visitor is offline.
document.addEventListener("DOMContentLoaded", () => {
  document.body.classList.add("app-ready");
  document.querySelectorAll("main > h2").forEach(el => el.classList.add("page-title"));
  document.querySelectorAll("main > .how").forEach(el => el.classList.add("page-subtitle"));
  document.querySelectorAll(".panel, .card").forEach(el => el.classList.add("motion-item"));

  import("https://cdn.jsdelivr.net/npm/motion@12.23.24/+esm")
    .then(({ animate, stagger }) => {
      const title = document.querySelector(".page-title");
      const subtitle = document.querySelector(".page-subtitle");
      if (title) animate(title, { opacity: [0, 1], y: [-14, 0] }, { duration: 0.48, ease: "easeOut" });
      if (subtitle) animate(subtitle, { opacity: [0, 1], y: [-10, 0] }, { duration: 0.48, delay: 0.08, ease: "easeOut" });
      animate(".motion-item", { opacity: [0, 1], y: [16, 0], scale: [0.985, 1] }, {
        duration: 0.42,
        delay: stagger(0.055, { startDelay: 0.13 }),
        ease: "easeOut"
      });

      const observer = new MutationObserver(records => {
        const added = records.flatMap(record => [...record.addedNodes])
          .filter(node => node.nodeType === 1)
          .flatMap(node => [node, ...node.querySelectorAll(".card, tr, .bar")])
          .filter(node => node.matches?.(".card, tr, .bar"));
        if (added.length) animate(added, { opacity: [0, 1], y: [8, 0] }, { duration: 0.28, delay: stagger(0.025), ease: "easeOut" });
      });
      observer.observe(document.querySelector("main"), { childList: true, subtree: true });
    })
    .catch(() => {});
});
