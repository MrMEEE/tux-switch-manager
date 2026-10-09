(() => {
  "use strict";
  document.addEventListener("submit", (event) => {
    const prompt = event.submitter?.dataset.confirmButton || event.target.dataset.confirm;
    if (prompt && !window.confirm(prompt)) event.preventDefault();
  });
  const container = document.getElementById("live-detail");
  if (!container) return;
  const connection = document.getElementById("connection");
  let delay = 1000;
  let refreshing = false;
  let pending = false;
  async function refresh() {
    // Leave all editing controls alone, including focused pending-change buttons.
    if (container.contains(document.activeElement)) {
      pending = true;
      return;
    }
    if (refreshing) { pending = true; return; }
    refreshing = true;
    try {
      const response = await fetch(container.dataset.statusUrl, {credentials: "same-origin", cache: "no-store"});
      if (response.status === 403 || response.status === 404 || response.redirected) {
        container.replaceChildren();
        connection.textContent = "Access changed. Sign in again or contact an administrator.";
        return;
      }
      if (!response.ok) throw new Error("Status unavailable");
      const data = await response.json();
      if (data.switch_id === Number(container.dataset.switchId)) {
        // The fragment is rendered by Django with automatic escaping, never device-provided HTML.
        container.innerHTML = data.html;
      }
    } catch (_) { connection.textContent = "Live status unavailable; retrying."; }
    finally { refreshing = false; }
  }
  container.addEventListener("focusout", () => {
    if (pending) { pending = false; window.setTimeout(refresh, 0); }
  });
  function connect() {
    const socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/switches/${container.dataset.switchId}/`);
    socket.onopen = () => { delay = 1000; connection.textContent = "● Live updates connected"; refresh(); };
    socket.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);
        if (event.event === "updated" && event.switch_id === Number(container.dataset.switchId)) refresh();
      } catch (_) { /* Ignore malformed notifications. */ }
    };
    socket.onclose = (event) => {
      connection.textContent = "Live updates disconnected.";
      if (event.code === 4403) { refresh(); return; }
      window.setTimeout(connect, delay + Math.random() * 250);
      delay = Math.min(delay * 2, 30000);
    };
    socket.onerror = () => socket.close();
  }
  connect();
  window.setInterval(refresh, 30000);
})();
