(() => {
  "use strict";
  const menuToggle = document.querySelector(".menu-toggle");
  if (menuToggle) {
    menuToggle.addEventListener("click", () => {
      const collapsed = document.body.classList.toggle("sidebar-collapsed");
      menuToggle.setAttribute("aria-expanded", String(!collapsed));
    });
  }
  const confirmedForms = new WeakSet();
  const confirmingForms = new Set();
  const submittingForms = new Set();
  const dirtyFields = new WeakSet();
  document.addEventListener("input", (event) => dirtyFields.add(event.target));
  document.addEventListener("change", (event) => dirtyFields.add(event.target));
  function showMessages(notices) {
    const target = document.getElementById("action-messages");
    if (!target) return;
    target.replaceChildren(...notices.map((notice) => {
      const element = document.createElement("div");
      element.className = `notice ${notice.tags || ""}`;
      element.setAttribute("role", notice.tags?.includes("error") ? "alert" : "status");
      element.textContent = notice.text;
      return element;
    }));
  }
  function openModal(dialog, acceptedValue) {
    const previousFocus = document.activeElement;
    dialog.returnValue = "cancel";
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => {
        if (previousFocus?.isConnected) previousFocus.focus();
        resolve(dialog.returnValue === acceptedValue);
      }, {once: true});
      dialog.showModal();
    });
  }
  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (form.matches("[data-configuration-editor]") && form.dataset.liveStale === "true") {
      event.preventDefault();
      showMessages([{text: "This editor is outdated. Reopen it before saving; your draft has not been submitted.", tags: "error"}]);
      return;
    }
    if (confirmedForms.delete(form)) return;
    const message = event.submitter?.dataset.confirmButton || form.dataset.confirm;
    if (!message) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const dialog = document.getElementById("confirmation-dialog");
    if (confirmingForms.size || dialog.open) return;
    const submitter = event.submitter;
    dialog.querySelector("#confirmation-message").textContent = message;
    dialog.querySelector("[data-confirm-accept]").classList.toggle("danger", submitter?.classList.contains("danger") || false);
    confirmingForms.add(form);
    try {
      if (await openModal(dialog, "confirm") && form.isConnected && (!submitter || submitter.isConnected && !submitter.disabled)) {
        confirmedForms.add(form);
        try {
          if (submitter) form.requestSubmit(submitter);
          else form.requestSubmit();
        } finally {
          confirmedForms.delete(form);
        }
      }
    } finally {
      confirmingForms.delete(form);
      const region = form.closest("[data-live-url]");
      if (region) region.dispatchEvent(new FocusEvent("focusout", {bubbles: true}));
    }
  });
  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (event.defaultPrevented || !form.matches("[data-live-submit], #live-detail form")) return;
    event.preventDefault();
    if (submittingForms.has(form)) return;
    const submitter = event.submitter;
    const data = submitter ? new FormData(form, submitter) : new FormData(form);
    submittingForms.add(form);
    const buttons = [...form.querySelectorAll('button, input[type="submit"]')];
    const disabled = buttons.map((button) => button.disabled);
    buttons.forEach((button) => {button.disabled = true;});
    try {
      const response = await fetch(new URL(form.getAttribute("action") || location.href, location.href), {
        method: "POST", body: data, credentials: "same-origin",
        headers: {"Accept": "application/json", "X-Live-Action": "true"},
      });
      if (!response.headers.get("content-type")?.includes("application/json")) {
        throw new Error("Action access expired or was denied. Sign in again or reopen the page.");
      }
      const result = await response.json();
      showMessages(result.messages || []);
      if (!response.ok) {
        if (!result.messages?.length) throw new Error("Action failed. Check access and application logs.");
        return;
      }
      if (result.redirect) {
        const target = new URL(result.redirect, location.href);
        if (target.origin !== location.origin) throw new Error("Unexpected action redirect.");
        if (target.pathname !== location.pathname) {
          location.assign(target.href);
          return;
        }
        if (target.hash) initializeConfiguration(document, target.hash.slice(1));
      }
      document.querySelectorAll("[data-live-url]").forEach((region) => region.dispatchEvent(new Event("live-refresh")));
    } catch (error) {
      showMessages([{text: error.message || "Action failed. Check your connection before retrying.", tags: "error"}]);
    } finally {
      buttons.forEach((button, index) => {button.disabled = disabled[index];});
      submittingForms.delete(form);
      form.closest("[data-live-url]")?.dispatchEvent(new Event("live-release"));
    }
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
    const review = event.target.closest("[data-configuration-go]");
    if (review) {
      event.preventDefault();
      selectConfiguration(review.closest("[data-configuration-workspace]"), review.dataset.configurationGo);
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
    return openModal(dialog, "trust");
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
      const response = await fetch(new URL(form.getAttribute("action") || location.href, location.href), {
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

  const connectionReports = new Map();
  document.querySelectorAll("[data-live-url]").forEach((container) => {
    if (container.parentElement?.closest("[data-live-url]")) return;
    connectionReports.set(container, "Live updates connecting…");
    if (container.dataset.liveBound === "true") {
      container.querySelectorAll("input:not([type=hidden]), select, textarea").forEach((field) => dirtyFields.add(field));
    }
    let socket;
    let delay = 1000;
    let pending = null;
    let revoked = false;
    let lastHTML = null;
    const report = (message) => {
      connectionReports.set(container, message);
      const reports = [...connectionReports.values()];
      const status = reports.find((value) => value.startsWith("Access changed")) ||
        reports.find((value) => !value.includes("connected") || value.includes("disconnected")) || message;
      document.querySelectorAll("#connection, .live-connection, #live-status").forEach((element) => {
        element.textContent = status;
      });
    };
    const key = (element, index) => element.dataset.liveKey || element.id || String(index);
    const fieldKey = (element, index) => {
      const form = element.closest("form");
      const owner = element.closest("[data-live-key]");
      const hidden = form ? [...form.querySelectorAll('input[type="hidden"]:not([name="csrfmiddlewaretoken"])')]
        .map((input) => `${input.name}:${input.value}`).join("|") : "";
      return `${owner?.dataset.liveKey || ""}|${form?.getAttribute("action") || ""}|${hidden}|${element.id || element.name || element.getAttribute("href") || index}|${["checkbox", "radio", "submit"].includes(element.type) || element.tagName === "BUTTON" ? element.value : ""}`;
    };
    function restoreValue(element, value) {
      if (element.tagName === "SELECT" && value && ![...element.options].some((option) => option.value === value)) {
        const option = new Option("Previously selected option (unavailable)", value);
        option.disabled = true;
        element.add(option);
      }
      element.value = value;
    }
    function apply(html) {
      if (html === lastHTML) return;
      const focusable = "input, select, textarea, button, a, summary, [tabindex]";
      const active = container.contains(document.activeElement) ? document.activeElement : null;
      const activeKey = active ? fieldKey(active, [...container.querySelectorAll(focusable)].indexOf(active)) : null;
      const cursor = active && ["INPUT", "TEXTAREA"].includes(active.tagName) && typeof active.selectionStart === "number" ?
        {start: active.selectionStart, end: active.selectionEnd, direction: active.selectionDirection} : null;
      if ([...confirmingForms].some((form) => container.contains(form)) ||
          [...submittingForms].some((form) => container.contains(form)) ||
          (verificationBusy && container.querySelector("[data-verify-candidate]"))) {
        pending = html;
        return;
      }
      const expanded = new Map([...container.querySelectorAll("details")]
        .map((element, index) => [key(element, index), element.open]));
      const values = new Map([...container.querySelectorAll("input:not([type=hidden]), select, textarea")]
        .map((element, index) => [fieldKey(element, index), {
          value: element.value, checked: element.checked, dirty: dirtyFields.has(element),
          selected: element.multiple ? [...element.selectedOptions].map((option) => option.value) : null,
          preserve: dirtyFields.has(element) || element === active,
        }]).filter(([, value]) => value.preserve));
      const scroll = new Map([...container.querySelectorAll("pre, .table-scroll")]
        .map((element, index) => [key(element, index), {top: element.scrollTop, left: element.scrollLeft}]));
      const errors = [...container.querySelectorAll(".errorlist")].map((element) => ({
        node: element.cloneNode(true), field: element.closest(".form-field")?.querySelector("[id]")?.id,
      }));
      // Only server-rendered, permission-filtered fragments enter live regions.
      const selection = container.tagName === "SELECT" ? container.value : null;
      const configurationSelection = container.querySelector("[data-configuration-workspace]")?.dataset.configurationSelected;
      container.innerHTML = html;
      errors.forEach(({node, field}) => {
        const target = field ? [...container.querySelectorAll("[id]")].find((element) => element.id === field)?.closest(".form-field") : container;
        if (target && !target.querySelector(".errorlist")) target.append(node);
      });
      initializeConfiguration(container, configurationSelection);
      if (selection !== null) restoreValue(container, selection);
      container.querySelectorAll("details").forEach((element, index) => {
        const previous = expanded.get(key(element, index));
        if (previous !== undefined) element.open = previous;
      });
      container.querySelectorAll("input:not([type=hidden]), select, textarea").forEach((element, index) => {
        const previous = values.get(fieldKey(element, index));
        if (!previous) return;
        restoreValue(element, previous.value);
        if (previous.selected) [...element.options].forEach((option) => {option.selected = previous.selected.includes(option.value);});
        if (element.type === "checkbox" || element.type === "radio") element.checked = previous.checked;
        if (previous.dirty) dirtyFields.add(element);
      });
      if (activeKey !== null) {
        const restored = [...container.querySelectorAll(focusable)].find((element, index) => fieldKey(element, index) === activeKey);
        restored?.focus({preventScroll: true});
        if (cursor && restored?.setSelectionRange) restored.setSelectionRange(cursor.start, cursor.end, cursor.direction);
      }
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
        if (pending !== null) apply(pending);
      });
    });
    container.addEventListener("live-release", () => {
      if (pending !== null) apply(pending);
    });
    function connect() {
      if (revoked) return;
      const parameters = new URLSearchParams({path: location.pathname});
      if (container.dataset.editorRevision) parameters.set("revision", container.dataset.editorRevision);
      if (container.dataset.editorProfile) parameters.set("profile", container.dataset.editorProfile);
      if (container.dataset.editorChange) {
        parameters.set("change", container.dataset.editorChange);
        parameters.set("token", container.dataset.editorToken || "");
      }
      socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${container.dataset.liveUrl}?${parameters}`);
      socket.onopen = () => {
        delay = 1000;
        report("● Live updates connected");
      };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data);
          if (event.event === "snapshot" && typeof event.html === "string") apply(event.html);
          if (event.event === "snapshot" && event.metadata) {
            if (typeof event.metadata.title === "string") document.title = event.metadata.title;
            if (typeof event.metadata.editor_stale === "boolean") {
              const form = document.querySelector("[data-configuration-editor]");
              if (form) {
                form.dataset.liveStale = String(event.metadata.editor_stale);
                form.querySelectorAll('button[type="submit"], button:not([type])').forEach((button) => {
                  button.disabled = event.metadata.editor_stale;
                });
              }
            }
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
          if (container.dataset.liveUrl.includes("/editor-state/")) document.querySelector("[data-configuration-editor]")?.remove();
          if (container.dataset.liveUrl.includes("/inventory-form/") || container.dataset.liveUrl.includes("/credential-form/")) {
            container.closest("form")?.replaceChildren();
          }
          if (container.dataset.liveUrl === "/ws/live/account/") document.getElementById("main-content")?.replaceChildren();
          if (["/ws/live/discovery/", "/ws/live/credentials/"].includes(container.dataset.liveUrl)) {
            document.getElementById("main-content")?.replaceChildren();
          }
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
