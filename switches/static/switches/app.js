(() => {
  "use strict";
  const menuToggle = document.querySelector(".menu-toggle");
  if (menuToggle) {
    menuToggle.addEventListener("click", () => {
      const collapsed = document.body.classList.toggle("sidebar-collapsed");
      menuToggle.setAttribute("aria-expanded", String(!collapsed));
    });
  }
  document.addEventListener("submit", (event) => {
    const prompt = event.submitter?.dataset.confirmButton || event.target.dataset.confirm;
    if (prompt && !window.confirm(prompt)) event.preventDefault();
  });
  function selectConfiguration(workspace, target) {
    const tabs = [...workspace.querySelectorAll("[data-configuration-tab]")];
    if (!tabs.length) return;
    const selected = tabs.find((tab) => tab.dataset.configurationTab === target) || tabs[0];
    workspace.dataset.configurationSelected = selected.dataset.configurationTab;
    tabs.forEach((tab) => {
      const active = tab === selected;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });
    workspace.querySelectorAll("[data-configuration-panel]").forEach((panel) => {
      panel.hidden = panel.id !== selected.dataset.configurationTab;
    });
    const current = workspace.querySelector("[data-configuration-current]");
    if (current) current.hidden = selected.dataset.configurationTab === "configuration-review" && !current.querySelector('[role="alert"]');
  }
  function initializeConfiguration(root, selected) {
    root.querySelectorAll("[data-configuration-workspace]").forEach((workspace) => {
      selectConfiguration(workspace, selected || location.hash.slice(1));
    });
  }
  initializeConfiguration(document);
  document.addEventListener("click", (event) => {
    const dismiss = event.target.closest("[data-https-dismiss]");
    if (dismiss) {
      dismiss.closest("details").open = false;
      return;
    }
    const tab = event.target.closest("[data-configuration-tab]");
    if (!tab) return;
    selectConfiguration(tab.closest("[data-configuration-workspace]"), tab.dataset.configurationTab);
  });
  document.addEventListener("keydown", (event) => {
    const tab = event.target.closest("[data-configuration-tab]");
    if (!tab || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const workspace = tab.closest("[data-configuration-workspace]");
    const tabs = [...workspace.querySelectorAll("[data-configuration-tab]")];
    const index = tabs.indexOf(tab);
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 :
      (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    selectConfiguration(workspace, tabs[next].dataset.configurationTab);
    tabs[next].focus();
  });
  window.addEventListener("hashchange", () => {
    if (location.hash.startsWith("#configure-") || location.hash === "#configuration-review") {
      initializeConfiguration(document);
    }
  });
  let verificationBusy = false;
  function approveHostKey(data) {
    const dialog = document.getElementById("host-key-dialog");
    dialog.querySelector('[data-host-key="address"]').textContent = `${data.address}:${data.port}`;
    dialog.querySelector('[data-host-key="algorithm"]').textContent = data.algorithm;
    dialog.querySelector('[data-host-key="fingerprint"]').textContent = data.fingerprint;
    dialog.returnValue = "cancel";
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "trust"), {once: true});
      dialog.showModal();
    });
  }
  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("[data-verify-candidate]")) return;
    event.preventDefault();
    const status = form.querySelector(".verification-status");
    if (verificationBusy) {
      status.textContent = "Another verification is in progress. Please wait.";
      return;
    }
    verificationBusy = true;
    const button = form.querySelector("button");
    button.disabled = true;
    const data = new FormData(form);
    const send = async () => {
      const response = await fetch(form.action, {
        method: "POST", body: data, credentials: "same-origin", headers: {"Accept": "application/json"},
      });
      if (!response.headers.get("content-type")?.includes("application/json")) {
        throw new Error("Verification access expired or was denied. Reload the page and sign in again.");
      }
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || "Verification failed.");
      return result;
    };
    try {
      status.textContent = "Checking credentials and NETCONF access...";
      let result = await send();
      if (result.status === "trust_required") {
        if (!await approveHostKey(result)) {
          status.textContent = "Cancelled. The host key was not trusted and no switch was added.";
          return;
        }
        data.set("trust_token", result.trust_token);
        status.textContent = "Verifying the approved host key and credentials...";
        result = await send();
      }
      if (result.status !== "added") throw new Error("Verification did not complete. Try again.");
      status.textContent = result.message;
      document.querySelectorAll("[data-live-url]").forEach((region) => region.dispatchEvent(new Event("live-refresh")));
    } catch (error) {
      status.textContent = error.message || "Verification failed. Check your connection and retry.";
    } finally {
      button.disabled = false;
      verificationBusy = false;
      const region = form.closest("[data-live-url]");
      button.blur();
      if (region) region.dispatchEvent(new FocusEvent("focusout", {bubbles: true}));
    }
  });

  document.querySelectorAll("[data-live-url]").forEach((container) => {
    const connection = document.getElementById("connection") || document.querySelector(".live-connection") || document.getElementById("live-status");
    let socket;
    let delay = 1000;
    let pending = null;
    let revoked = false;
    let lastHTML = null;
    const report = (message) => {
      if (connection) connection.textContent = message;
    };
    const key = (element, index) => element.dataset.liveKey || element.id || String(index);
    const fieldKey = (element, index) => {
      const form = element.closest("form");
      const owner = element.closest("[data-live-key]");
      const hidden = form ? [...form.querySelectorAll('input[type="hidden"]:not([name="csrfmiddlewaretoken"])')]
        .map((input) => `${input.name}:${input.value}`).join("|") : "";
      return `${owner?.dataset.liveKey || ""}|${form?.getAttribute("action") || ""}|${hidden}|${element.name || element.id || index}`;
    };
    function restoreValue(element, value) {
      if (element.tagName === "SELECT" && value && ![...element.options].some((option) => option.value === value)) {
        const option = new Option("Previously selected credential (unavailable)", value);
        option.disabled = true;
        element.add(option);
      }
      element.value = value;
    }
    function apply(html) {
      if (html === lastHTML) return;
      const focusedTab = container.contains(document.activeElement) && document.activeElement.matches("[data-configuration-tab]") ?
        document.activeElement.id : null;
      if ((verificationBusy && container.querySelector("[data-verify-candidate]")) ||
          container === document.activeElement || (container.contains(document.activeElement) && !focusedTab)) {
        pending = html;
        return;
      }
      const expanded = new Map([...container.querySelectorAll("details")]
        .map((element, index) => [key(element, index), element.open]));
      const values = new Map([...container.querySelectorAll("input:not([type=hidden]), select, textarea")]
        .map((element, index) => [fieldKey(element, index), {value: element.value, checked: element.checked}]));
      const scroll = new Map([...container.querySelectorAll("pre, .table-scroll")]
        .map((element, index) => [key(element, index), {top: element.scrollTop, left: element.scrollLeft}]));
      // Only server-rendered, permission-filtered fragments enter live regions.
      const selection = container.tagName === "SELECT" ? container.value : null;
      const configurationSelection = container.querySelector("[data-configuration-workspace]")?.dataset.configurationSelected;
      container.innerHTML = html;
      initializeConfiguration(container, configurationSelection);
      if (focusedTab) container.querySelector(`[id="${focusedTab}"]`)?.focus({preventScroll: true});
      if (selection !== null) restoreValue(container, selection);
      container.querySelectorAll("details").forEach((element, index) => {
        const previous = expanded.get(key(element, index));
        if (previous !== undefined) element.open = previous;
      });
      container.querySelectorAll("input:not([type=hidden]), select, textarea").forEach((element, index) => {
        const previous = values.get(fieldKey(element, index));
        if (!previous) return;
        restoreValue(element, previous.value);
        if (element.type === "checkbox" || element.type === "radio") element.checked = previous.checked;
      });
      container.querySelectorAll("pre, .table-scroll").forEach((element, index) => {
        const previous = scroll.get(key(element, index));
        if (previous) {
          element.scrollTop = previous.top;
          element.scrollLeft = previous.left;
        }
      });
      lastHTML = html;
      pending = null;
    }
    container.addEventListener("focusout", () => {
      queueMicrotask(() => {
        if (pending !== null && container !== document.activeElement && !container.contains(document.activeElement)) apply(pending);
      });
    });
    function connect() {
      if (revoked) return;
      socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${container.dataset.liveUrl}`);
      socket.onopen = () => {
        delay = 1000;
        report("● Live updates connected");
      };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data);
          if (event.event === "snapshot" && typeof event.html === "string") apply(event.html);
          if (event.event === "snapshot" && event.metadata) {
            document.querySelectorAll("[data-live-text]").forEach((element) => {
              const value = event.metadata[element.dataset.liveText];
              if (typeof value === "string") element.textContent = value;
            });
          }
          if (event.event === "error") report(event.message);
        } catch (error) {
          report("Could not read a live update. Reconnecting.");
          socket.close();
        }
      };
      socket.onclose = (event) => {
        if (event.code === 4403) {
          revoked = true;
          pending = null;
          container.replaceChildren();
          document.querySelectorAll("[data-live-text]").forEach((element) => element.replaceChildren());
          report("Access changed. Sign in again or contact an administrator.");
          return;
        }
        report("Live updates disconnected; reconnecting.");
        window.setTimeout(connect, delay + Math.random() * 250);
        delay = Math.min(delay * 2, 30000);
      };
      socket.onerror = () => socket.close();
    }
    connect();
    container.addEventListener("live-refresh", () => {
      if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({event: "refresh"}));
    });
    // Resynchronize over the socket after missed events and recheck session access.
    window.setInterval(() => {
      if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({event: "refresh"}));
    }, 30000);
  });
})();
