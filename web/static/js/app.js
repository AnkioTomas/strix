(function () {
  const $ = (id) => document.getElementById(id);
  const api = window.StrixAPI;
  const penna = window.StrixPenna;

  let selected = null;
  let tasksCache = [];
  let activeTab = "overview";
  let viewerLoadedFor = null;
  let findingsRenderer = null;
  let reportRenderer = null;

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function artifactUrl(taskId, relPath) {
    const clean = String(relPath || "").replace(/^(\.\/)+/, "").replace(/^\/+/, "");
    return `/api/v1/tasks/${encodeURIComponent(taskId)}/artifacts/${clean.split("/").map(encodeURIComponent).join("/")}`;
  }

  function ensureFindingsRenderer() {
    if (!findingsRenderer) {
      findingsRenderer = penna.createRenderer($("findingsView"));
    }
    return findingsRenderer;
  }

  function ensureReportRenderer() {
    if (!reportRenderer) {
      reportRenderer = penna.createRenderer($("reportView"));
    }
    return reportRenderer;
  }

  function renderWithPenna(renderer, markdown, taskId) {
    const md = penna.rewriteArtifactLinks(markdown, taskId);
    renderer.render(md || "> [!NOTE]\n> （空内容）\n");
  }

  function showCreate(show) {
    $("createPanel").classList.toggle("hidden", !show);
    if (show) {
      $("emptyState").classList.add("hidden");
      $("detailPanel").classList.add("hidden");
    } else if (!selected) {
      $("emptyState").classList.remove("hidden");
      $("detailPanel").classList.add("hidden");
    } else {
      $("emptyState").classList.add("hidden");
      $("detailPanel").classList.remove("hidden");
    }
  }

  function setTab(name) {
    activeTab = name;
    document.querySelectorAll(".tab").forEach((el) => {
      el.classList.toggle("active", el.dataset.tab === name);
    });
    document.querySelectorAll(".tab-pane").forEach((el) => {
      el.classList.toggle("active", el.id === `tab-${name}`);
    });
    if (name === "viewer") loadViewer();
    if (name === "report") loadReport();
    if (name === "findings") loadFindings();
    if (name === "artifacts") loadArtifacts();
    if (name === "chat") loadMessages();
  }

  function currentTask() {
    return tasksCache.find((t) => t.id === selected) || null;
  }

  function renderTaskList() {
    const list = $("taskList");
    if (!tasksCache.length) {
      list.innerHTML = `<li class="muted" style="cursor:default">暂无任务</li>`;
      return;
    }
    list.innerHTML = tasksCache
      .map((t) => {
        const title = t.target || t.source_url || t.id;
        return `<li class="${t.id === selected ? "active" : ""}" data-id="${esc(t.id)}">
          <div class="task-title">${esc(title)}</div>
          <div class="task-sub">
            <span class="status-dot ${esc(t.status)}"></span>
            <span>${esc(t.status)}</span>
            <span>${esc(t.type)}</span>
          </div>
        </li>`;
      })
      .join("");
    list.querySelectorAll("li[data-id]").forEach((li) => {
      li.onclick = () => selectTask(li.dataset.id);
    });
  }

  function selectTask(id) {
    selected = id;
    viewerLoadedFor = null;
    showCreate(false);
    $("emptyState").classList.add("hidden");
    $("detailPanel").classList.remove("hidden");
    $("selectedId").textContent = id;
    renderTaskList();
    renderOverview();
    setTab(activeTab);
    refreshDetails();
  }

  function renderOverview() {
    const t = currentTask();
    if (!t) return;
    $("selectedMeta").textContent = `${t.status} · ${t.scan_mode || "—"} · ${t.created_at || ""}`;
    const rows = [
      ["状态", t.status],
      ["类型", t.type],
      ["目标", t.target || t.source_url || "—"],
      ["Run", t.run_name || "—"],
      ["Viewer 代理", t.viewer_proxy_url || "（运行后生成）"],
      ["错误", t.error || "—"],
    ];
    $("overviewKv").innerHTML = rows
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
      .join("");
  }

  async function loadViewer() {
    const t = currentTask();
    const frame = $("viewerFrame");
    const hint = $("viewerHint");
    const direct = $("viewerDirect");
    if (!t) return;
    if (t.viewer_url) {
      direct.href = t.viewer_url;
      direct.textContent = "直连调试链接";
    } else {
      direct.href = "#";
      direct.textContent = "直连不可用";
    }
    if (!t.viewer_proxy_url) {
      frame.removeAttribute("src");
      hint.textContent = "任务尚未启动 Viewer（queued/starting 或已结束无会话）";
      return;
    }
    hint.textContent = "同源反代 · 需已记住 Token（session cookie）";
    if (viewerLoadedFor !== t.id) {
      try {
        await api.ensureSession();
      } catch (e) {
        hint.textContent = `会话失败: ${e.message}`;
        return;
      }
      frame.src = t.viewer_proxy_url;
      viewerLoadedFor = t.id;
    }
  }

  async function loadMessages() {
    if (!selected) return;
    try {
      const data = await api.api(`/api/v1/tasks/${selected}/messages`);
      const lines = (data.messages || []).map((m) => {
        const flag = m.delivered ? "delivered" : "pending";
        return `[${m.created_at || ""}] ${m.role} (${flag})\n${m.content}`;
      });
      $("chatLog").textContent = lines.join("\n\n") || "(暂无消息)";
    } catch (e) {
      $("chatLog").textContent = e.message;
    }
  }

  async function loadFindings() {
    if (!selected) return;
    try {
      const findings = await api.api(`/api/v1/tasks/${selected}/results`).catch(() => ({ findings: [] }));
      const md = penna.findingsToMarkdown(findings.findings || []);
      renderWithPenna(ensureFindingsRenderer(), md, selected);
    } catch (e) {
      renderWithPenna(
        ensureFindingsRenderer(),
        `> [!CAUTION]\n> 加载失败：${e.message}\n`,
        selected
      );
    }
  }

  async function loadReport() {
    if (!selected) return;
    try {
      const data = await api.api(`/api/v1/tasks/${selected}/report`);
      const content = data.content || "> [!NOTE]\n> 无报告\n";
      renderWithPenna(ensureReportRenderer(), content, selected);
    } catch (e) {
      renderWithPenna(
        ensureReportRenderer(),
        `> [!CAUTION]\n> ${e.message}\n`,
        selected
      );
    }
  }

  async function loadArtifacts() {
    if (!selected) return;
    try {
      const data = await api.api(`/api/v1/tasks/${selected}/artifacts`);
      const rows = data.artifacts || [];
      $("artifactsBody").innerHTML =
        rows
          .map((a) => {
            const href = artifactUrl(selected, a.path);
            return `<tr>
              <td>${esc(a.name)}</td>
              <td><code>${esc(a.path)}</code></td>
              <td>${esc(a.size)}</td>
              <td><a class="muted" href="${esc(href)}" download>下载</a></td>
            </tr>`;
          })
          .join("") || `<tr><td colspan="4" class="muted">暂无工件</td></tr>`;
    } catch (e) {
      $("artifactsBody").innerHTML = `<tr><td colspan="4">${esc(e.message)}</td></tr>`;
    }
  }

  async function loadEvents() {
    if (!selected) return;
    try {
      const data = await api.api(`/api/v1/tasks/${selected}/events`);
      $("events").textContent =
        (data.events || [])
          .map((e) => `[${e.type || "event"}] ${e.message || ""}`)
          .join("\n") || "(暂无事件)";
    } catch (e) {
      $("events").textContent = e.message;
    }
  }

  async function refreshDetails() {
    renderOverview();
    await Promise.all([loadEvents(), loadFindings()]);
    if (activeTab === "viewer") await loadViewer();
    if (activeTab === "chat") await loadMessages();
    if (activeTab === "report") await loadReport();
    if (activeTab === "artifacts") await loadArtifacts();
  }

  async function refresh() {
    try {
      const data = await api.api("/api/v1/tasks");
      tasksCache = data.tasks || [];
      renderTaskList();
      if (selected) {
        if (!tasksCache.some((t) => t.id === selected)) {
          selected = null;
          viewerLoadedFor = null;
          showCreate(false);
          $("detailPanel").classList.add("hidden");
          $("emptyState").classList.remove("hidden");
        } else {
          await refreshDetails();
        }
      }
      await refreshAdmission();
    } catch (e) {
      $("taskList").innerHTML = `<li>${esc(e.message)}</li>`;
    }
  }

  async function refreshAdmission() {
    try {
      const h = await fetch("/health").then((r) => r.json());
      const a = h.admission || {};
      const sys = a.system || {};
      $("admissionHint").textContent =
        `queued=${h.queued_tasks} running=${h.running_tasks} ` +
        `slots=${a.allowed_slots ?? "?"} (${a.reason || "n/a"}) ` +
        `load=${sys.load_1m ?? "?"} cpus=${sys.cpu_count ?? "?"}`;
    } catch (e) {
      $("admissionHint").textContent = `健康检查失败: ${e.message}`;
    }
  }

  $("apiKey").value = localStorage.getItem(api.KEY_STORAGE) || "";

  $("saveKey").onclick = async () => {
    api.setKey($("apiKey").value);
    try {
      await api.ensureSession();
      alert("Token 已记住，并写入会话 Cookie（供 Viewer iframe）");
    } catch (e) {
      alert(`Token 已本地保存，但会话失败: ${e.message}`);
    }
  };

  $("clearSession").onclick = async () => {
    await api.clearSession();
    viewerLoadedFor = null;
    $("viewerFrame").removeAttribute("src");
  };

  $("sidebarToggle").onclick = () => $("sidebar").classList.toggle("open");
  $("newTaskBtn").onclick = () => showCreate(true);
  $("cancelCreate").onclick = () => showCreate(false);

  $("taskType").onchange = () => {
    const audit = $("taskType").value === "audit";
    $("auditFields").classList.toggle("hidden", !audit);
    $("pentestFields").classList.toggle("hidden", audit);
  };

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.onclick = () => setTab(tab.dataset.tab);
  });

  $("createTask").onclick = async () => {
    const type = $("taskType").value;
    const body = {
      type,
      scan_mode: $("scanMode").value,
      instruction: $("instruction").value || null,
    };
    if (type === "pentest") body.target = $("target").value.trim();
    else
      body.source = {
        type: "git",
        url: $("gitUrl").value.trim(),
        branch: $("gitBranch").value.trim() || null,
      };
    try {
      await api.ensureSession();
      const task = await api.api("/api/v1/tasks", { method: "POST", body: JSON.stringify(body) });
      showCreate(false);
      await refresh();
      selectTask(task.id);
    } catch (e) {
      alert(e.message);
    }
  };

  $("sendMsg").onclick = async () => {
    if (!selected) return alert("先选任务");
    try {
      await api.api(`/api/v1/tasks/${selected}/messages`, {
        method: "POST",
        body: JSON.stringify({ content: $("message").value }),
      });
      $("message").value = "";
      await loadMessages();
    } catch (e) {
      alert(e.message);
    }
  };

  $("retryBtn").onclick = async () => {
    if (!selected) return;
    try {
      const t = await api.api(`/api/v1/tasks/${selected}/retry`, { method: "POST" });
      await refresh();
      selectTask(t.id);
    } catch (e) {
      alert(e.message);
    }
  };

  $("retestBtn").onclick = async () => {
    if (!selected) return;
    try {
      const t = await api.api(`/api/v1/tasks/${selected}/retest`, { method: "POST" });
      await refresh();
      selectTask(t.id);
    } catch (e) {
      alert(e.message);
    }
  };

  $("cancelBtn").onclick = async () => {
    if (!selected) return;
    try {
      await api.api(`/api/v1/tasks/${selected}/cancel`, { method: "POST" });
      await refresh();
    } catch (e) {
      alert(e.message);
    }
  };

  $("downloadReport").onclick = async () => {
    if (!selected) return;
    try {
      const data = await api.api(`/api/v1/tasks/${selected}/report`);
      const blob = new Blob([data.content || ""], { type: "text/markdown" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `${selected}-report.md`;
      a.click();
    } catch (e) {
      alert(e.message);
    }
  };

  $("refreshAll").onclick = refresh;

  if (api.getKey()) {
    api.ensureSession().catch(() => {});
  }
  refresh();
  setInterval(refresh, 8000);
})();
