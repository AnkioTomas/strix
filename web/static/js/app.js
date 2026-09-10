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
  let findingsCache = [];
  let selectedFindingId = null;
  /** @type {{ parentId: string, action: string } | null} */
  let createDraft = null;

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

  function slugifyHeading(text) {
    const base = String(text || "")
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{N}]+/gu, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64);
    return base || "section";
  }

  function clearReportToc() {
    const toc = $("reportToc");
    if (!toc) return;
    toc.innerHTML = "";
    toc.classList.add("hidden");
  }

  function buildReportToc() {
    const view = $("reportView");
    const toc = $("reportToc");
    if (!view || !toc) return;
    const headings = Array.from(view.querySelectorAll("h1, h2")).filter(
      (h) => h.textContent && h.textContent.trim()
    );
    if (!headings.length) {
      clearReportToc();
      return;
    }

    const used = new Set();
    const links = headings.map((heading, index) => {
      let id = heading.id;
      if (!id) {
        const base = slugifyHeading(heading.textContent);
        id = base;
        let n = 2;
        while (used.has(id) || document.getElementById(id)) {
          id = `${base}-${n++}`;
        }
        heading.id = id;
      }
      used.add(id);
      const level = heading.tagName === "H1" ? 1 : 2;
      return `<a class="report-toc-link level-${level}" href="#${esc(id)}" data-toc-id="${esc(id)}">${esc(
        heading.textContent.trim()
      )}</a>`;
    });

    toc.innerHTML = `<span class="report-toc-title">目录</span>${links.join("")}`;
    toc.classList.remove("hidden");

    toc.querySelectorAll(".report-toc-link").forEach((anchor) => {
      anchor.onclick = (event) => {
        event.preventDefault();
        const id = anchor.getAttribute("data-toc-id");
        const target = id ? document.getElementById(id) : null;
        if (!target) return;
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        toc.querySelectorAll(".report-toc-link").forEach((el) => {
          el.classList.toggle("active", el === anchor);
        });
        history.replaceState(null, "", `#${id}`);
      };
    });
  }

  function scheduleReportToc() {
    // Penna may paint headings after render() returns.
    queueMicrotask(buildReportToc);
    setTimeout(buildReportToc, 60);
  }

  function showCreate(show) {
    if (show) $("importPanel").classList.add("hidden");
    $("createPanel").classList.toggle("hidden", !show);
    if (show) {
      $("emptyState").classList.add("hidden");
      $("detailPanel").classList.add("hidden");
      return;
    }
    if (!$("importPanel").classList.contains("hidden")) return;
    if (!selected) {
      $("emptyState").classList.remove("hidden");
      $("detailPanel").classList.add("hidden");
    } else {
      $("emptyState").classList.add("hidden");
      $("detailPanel").classList.remove("hidden");
    }
  }

  function syncCreateTypeFields() {
    const audit = $("taskType").value === "audit";
    $("auditFields").classList.toggle("hidden", !audit);
    $("pentestFields").classList.toggle("hidden", audit);
  }

  function resetCreateForm() {
    createDraft = null;
    const title = $("createPanel").querySelector("h2");
    if (title) title.textContent = "新建任务";
    $("createTask").textContent = "创建";
    $("taskName").value = "";
    $("taskNotes").value = "";
    $("taskHeld").checked = false;
    $("taskType").value = "pentest";
    $("scanMode").value = "deep";
    $("target").value = "";
    $("gitUrl").value = "";
    $("gitBranch").value = "";
    $("instruction").value = "";
    $("attachments").value = "";
    syncCreateTypeFields();
    updateAttachmentsHint();
  }

  function fillCreateFormFromTask(t, action) {
    createDraft = { parentId: t.id, action };
    const title = $("createPanel").querySelector("h2");
    if (title) title.textContent = action === "retry" ? "重试任务" : "新建任务";
    $("createTask").textContent = action === "retry" ? "创建重试" : "创建";
    $("taskName").value = t.name || "";
    $("taskNotes").value = t.notes || "";
    $("taskHeld").checked = false;
    $("taskType").value = t.type || "pentest";
    $("scanMode").value = t.scan_mode || "deep";
    $("instruction").value = t.instruction || "";
    $("target").value = t.type === "pentest" ? t.target || "" : "";
    $("gitUrl").value = t.type === "audit" ? t.source_url || "" : "";
    $("gitBranch").value = t.source_branch || "";
    $("attachments").value = "";
    syncCreateTypeFields();
    updateAttachmentsHint();
  }

  function showImport(show) {
    if (show) $("createPanel").classList.add("hidden");
    $("importPanel").classList.toggle("hidden", !show);
    if (show) {
      $("emptyState").classList.add("hidden");
      $("detailPanel").classList.add("hidden");
      $("importResult").classList.add("hidden");
      $("importResult").textContent = "";
      return;
    }
    if (!$("createPanel").classList.contains("hidden")) return;
    if (!selected) {
      $("emptyState").classList.remove("hidden");
      $("detailPanel").classList.add("hidden");
    } else {
      $("emptyState").classList.add("hidden");
      $("detailPanel").classList.remove("hidden");
    }
  }

  const TERMINAL = new Set(["completed", "failed", "cancelled"]);
  const ACTIVE = new Set(["queued", "starting", "running", "cancelling"]);
  const DELETABLE = new Set(["completed", "failed", "cancelled", "held"]);

  function updateActionButtons() {
    const t = currentTask();
    const terminal = !!(t && TERMINAL.has(t.status));
    const active = !!(t && ACTIVE.has(t.status));
    const held = !!(t && t.status === "held");
    const queued = !!(t && t.status === "queued");
    $("deleteBtn").disabled = !(t && DELETABLE.has(t.status));
    $("retryBtn").disabled = !terminal;
    $("retestBtn").disabled = !terminal;
    $("resumeBtn").disabled = !terminal;
    $("refreshReportBtn").disabled = !(terminal || active);
    $("cancelBtn").disabled = !active;
    $("holdBtn").disabled = !queued;
    $("releaseBtn").disabled = !held;
    $("renameBtn").disabled = !t;
    $("saveNotesBtn").disabled = !t;
  }

  function taskDisplayName(t) {
    return (t && (t.name || t.target || t.source_url || t.id)) || "—";
  }

  function setTab(name) {
    activeTab = name;
    document.querySelectorAll(".tab").forEach((el) => {
      el.classList.toggle("active", el.dataset.tab === name);
    });
    document.querySelectorAll(".tab-pane").forEach((el) => {
      el.classList.toggle("active", el.id === `tab-${name}`);
    });
    document.querySelector(".app")?.classList.toggle("viewer-focus", name === "viewer");
    $("detailPanel")?.classList.toggle("viewer-mode", name === "viewer");
    if (name === "viewer") loadViewer();
    if (name === "report") loadReport();
    if (name === "findings") loadFindings();
    if (name === "artifacts") loadArtifacts();
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
        const title = taskDisplayName(t);
        const subTarget = t.name && (t.target || t.source_url)
          ? `<div class="task-sub muted">${esc(t.target || t.source_url)}</div>`
          : "";
        return `<li class="${t.id === selected ? "active" : ""}" data-id="${esc(t.id)}">
          <div class="task-title">${esc(title)}</div>
          ${subTarget}
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
    selectedFindingId = null;
    findingsCache = [];
    showFindingsList();
    showCreate(false);
    $("emptyState").classList.add("hidden");
    $("detailPanel").classList.remove("hidden");
    const cur = currentTask();
    $("selectedId").textContent = cur ? taskDisplayName(cur) : id;
    $("selectedId").title = id;
    renderTaskList();
    renderOverview();
    setTab(activeTab);
    refreshDetails();
  }

  function formatUtc8(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    const parts = new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(d);
    const get = (type) => parts.find((p) => p.type === type)?.value || "";
    return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")} (UTC+8)`;
  }

  function formatDuration(seconds) {
    if (seconds == null || !Number.isFinite(Number(seconds))) return "—";
    let s = Math.max(0, Math.floor(Number(seconds)));
    const h = Math.floor(s / 3600);
    s %= 3600;
    const m = Math.floor(s / 60);
    const sec = s % 60;
    if (h > 0) return `${h}h ${m}m ${sec}s`;
    if (m > 0) return `${m}m ${sec}s`;
    return `${sec}s`;
  }

  function formatTokens(n) {
    if (n == null) return "—";
    const v = Number(n);
    if (!Number.isFinite(v)) return "—";
    return v.toLocaleString("en-US");
  }

  function renderOverview() {
    const t = currentTask();
    if (!t) return;
    const started = t.scan_started_at || t.started_at;
    const finished = t.scan_finished_at || t.finished_at;
    let duration = t.duration_seconds;
    if ((duration == null || !Number.isFinite(Number(duration))) && started) {
      const startMs = Date.parse(started);
      const endMs = finished ? Date.parse(finished) : Date.now();
      if (!Number.isNaN(startMs) && !Number.isNaN(endMs)) {
        duration = Math.max(0, (endMs - startMs) / 1000);
      }
    }
    const usage = t.llm_usage || {};
    $("selectedMeta").textContent = `${t.status} · ${t.scan_mode || "—"} · ${formatUtc8(t.created_at)}`;
    const rows = [
      ["名称", t.name || "（未命名）"],
      ["状态", t.status],
      ["类型", t.type],
      ["目标", t.target || t.source_url || "—"],
      ["动作", t.action || "—"],
      ["Scan mode", t.scan_mode || "—"],
      ["Run", t.run_name || "—"],
      ["任务 ID", t.id],
      ["启动时间", formatUtc8(started)],
      ["结束时间", finished ? formatUtc8(finished) : "（进行中）"],
      ["运行耗时", formatDuration(duration)],
      ["Token 输入", formatTokens(usage.input_tokens)],
      ["Token 输出", formatTokens(usage.output_tokens)],
      ["Token 缓存命中", formatTokens(usage.cached_tokens)],
      ["Token 缓存写入", formatTokens(usage.cache_write_tokens)],
      ["Token 总计", formatTokens(usage.total_tokens)],
      ["请求次数", formatTokens(usage.requests)],
      ["Viewer 代理", t.viewer_proxy_url || "（运行后生成）"],
      ["错误", t.error || "—"],
    ];
    $("overviewKv").innerHTML = rows
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
      .join("");
    const notesEl = $("overviewNotes");
    if (notesEl && document.activeElement !== notesEl) {
      notesEl.value = t.notes || "";
    }
    updateActionButtons();
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

  function showFindingsList() {
    $("findingsListPane").classList.remove("hidden");
    $("findingsDetailPane").classList.add("hidden");
    selectedFindingId = null;
  }

  function showFindingDetail(findingId) {
    const finding = findingsCache.find((f) => f.id === findingId);
    if (!finding) return;
    selectedFindingId = findingId;
    $("findingsListPane").classList.add("hidden");
    $("findingsDetailPane").classList.remove("hidden");
    renderWithPenna(ensureFindingsRenderer(), penna.findingToMarkdown(finding), selected);
    renderFindingsTable();
  }

  function renderFindingsTable() {
    const body = $("findingsBody");
    const count = $("findingsCount");
    if (!findingsCache.length) {
      count.textContent = "暂无漏洞";
      body.innerHTML = `<tr><td colspan="4" class="muted">该任务暂无漏洞</td></tr>`;
      return;
    }
    count.textContent = `共 ${findingsCache.length} 条 · 点击查看详情`;
    body.innerHTML = findingsCache
      .map((f) => {
        const sev = String(f.severity || "unknown").toLowerCase();
        const where = penna.locationLabel(f);
        return `<tr data-id="${esc(f.id)}" class="${f.id === selectedFindingId ? "active" : ""}">
          <td><span class="sev-${esc(sev)}">${esc((f.severity || "unknown").toUpperCase())}</span></td>
          <td>${esc(f.title || "Untitled")}</td>
          <td>${esc(where)}</td>
          <td>${esc(f.confidence || "—")}</td>
        </tr>`;
      })
      .join("");
    body.querySelectorAll("tr[data-id]").forEach((tr) => {
      tr.onclick = () => showFindingDetail(tr.dataset.id);
    });
  }

  async function loadFindings() {
    if (!selected) return;
    try {
      const findings = await api.api(`/api/v1/tasks/${selected}/results`).catch(() => ({ findings: [] }));
      findingsCache = findings.findings || [];
      if (selectedFindingId && findingsCache.some((f) => f.id === selectedFindingId)) {
        showFindingDetail(selectedFindingId);
      } else {
        showFindingsList();
        renderFindingsTable();
      }
    } catch (e) {
      findingsCache = [];
      showFindingsList();
      $("findingsCount").textContent = "加载失败";
      $("findingsBody").innerHTML = `<tr><td colspan="4">${esc(e.message)}</td></tr>`;
    }
  }

  async function loadReport() {
    if (!selected) return;
    try {
      const data = await api.api(`/api/v1/tasks/${selected}/report`);
      const content = data.content || "> [!NOTE]\n> 无报告\n";
      renderWithPenna(ensureReportRenderer(), content, selected);
      scheduleReportToc();
    } catch (e) {
      clearReportToc();
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
              <td><code>${esc(a.path.replace(/^workspace\//, ""))}</code></td>
              <td>${esc(a.size)}</td>
              <td><a class="muted" href="${esc(href)}" download>下载</a></td>
            </tr>`;
          })
          .join("") || `<tr><td colspan="3" class="muted">workspace 为空或尚未生成</td></tr>`;
    } catch (e) {
      $("artifactsBody").innerHTML = `<tr><td colspan="3">${esc(e.message)}</td></tr>`;
    }
  }

  async function refreshDetails() {
    renderOverview();
    await loadFindings();
    if (activeTab === "viewer") await loadViewer();
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
          selectedFindingId = null;
          findingsCache = [];
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
      const cpus = Number(sys.cpu_count) || 1;
      const load = Number(sys.load_1m);
      const memTotal = Number(sys.mem_total_bytes) || 0;
      const memAvail = Number(sys.mem_available_bytes) || 0;
      const slots = a.allowed_slots;
      const reason = String(a.reason || "");

      const loadRatio = Number.isFinite(load) ? Math.min(load / Math.max(cpus, 1), 2) / 2 : 0;
      const loadPct = Math.round(loadRatio * 100);
      const loadFill = $("loadFill");
      loadFill.style.width = `${loadPct}%`;
      loadFill.classList.remove("warn", "danger");
      if (loadRatio >= 0.85) loadFill.classList.add("danger");
      else if (loadRatio >= 0.6) loadFill.classList.add("warn");
      $("loadValue").textContent = Number.isFinite(load)
        ? `${load.toFixed(2)} / ${cpus}`
        : "—";

      const memRatio = memTotal > 0 ? memAvail / memTotal : 0;
      const memFill = $("memFill");
      memFill.style.width = `${Math.round(memRatio * 100)}%`;
      memFill.classList.remove("warn", "danger");
      if (memRatio > 0 && memRatio < 0.12) memFill.classList.add("danger");
      else if (memRatio > 0 && memRatio < 0.25) memFill.classList.add("warn");
      $("memValue").textContent = memTotal
        ? `${formatBytes(memAvail)} · ${Math.round(memRatio * 100)}%`
        : "—";

      $("statRunning").textContent = String(h.running_tasks ?? 0);
      $("statQueued").textContent = String(h.queued_tasks ?? 0);
      $("statSlots").textContent = slots == null ? "—" : String(slots);

      const pill = $("admitPill");
      const paused = slots === 0 || /pause|pressure|memory|load/i.test(reason);
      const down = h.status && h.status !== "ok";
      pill.className = "admit-pill " + (down ? "down" : paused ? "paused" : "ok");
      pill.textContent = down
        ? "服务降级"
        : paused
          ? humanReason(reason) || "排队等待"
          : "可调度";
      pill.title = reason || "";
    } catch (e) {
      const pill = $("admitPill");
      if (pill) {
        pill.className = "admit-pill down";
        pill.textContent = "健康检查失败";
        pill.title = e.message;
      }
    }
  }

  function formatBytes(n) {
    if (!n || n <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let v = n;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
  }

  function humanReason(reason) {
    const r = String(reason || "");
    if (/memory/i.test(r)) return "内存不足";
    if (/load/i.test(r)) return "负载过高";
    if (/pause/i.test(r)) return "准入暂停";
    if (/^ok/i.test(r)) return "可调度";
    return r.replace(/^ok:?/, "").trim() || "";
  }

  function updateAttachmentsHint() {
    const input = $("attachments");
    const hint = $("attachmentsHint");
    if (!input || !hint) return;
    const files = Array.from(input.files || []);
    if (!files.length) {
      hint.textContent = createDraft
        ? "父任务附件会自动复制；也可另加新附件。"
        : "可选。例如 PoC、wordlist、凭证说明。";
      return;
    }
    hint.textContent = `已选 ${files.length} 个：${files.map((f) => f.name).join(", ")}`;
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
  $("newTaskBtn").onclick = () => {
    showImport(false);
    resetCreateForm();
    showCreate(true);
  };
  $("cancelCreate").onclick = () => {
    resetCreateForm();
    showCreate(false);
  };
  $("importTaskBtn").onclick = () => {
    resetCreateForm();
    showCreate(false);
    showImport(true);
  };
  $("cancelImport").onclick = () => showImport(false);
  $("attachments").onchange = updateAttachmentsHint;
  $("findingsBack").onclick = () => {
    showFindingsList();
    renderFindingsTable();
  };

  $("taskType").onchange = syncCreateTypeFields;

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.onclick = () => setTab(tab.dataset.tab);
  });

  $("createTask").onclick = async () => {
    const type = $("taskType").value;
    const files = Array.from($("attachments").files || []);
    const form = new FormData();
    form.append("type", type);
    form.append("scan_mode", $("scanMode").value);
    const taskName = $("taskName").value.trim();
    if (taskName) form.append("name", taskName);
    const notes = $("taskNotes").value.trim();
    if (notes) form.append("notes", notes);
    if ($("taskHeld").checked) form.append("held", "true");
    const instruction = $("instruction").value.trim();
    if (instruction) form.append("instruction", instruction);
    if (type === "pentest") {
      form.append("target", $("target").value.trim());
    } else {
      form.append("source_type", "git");
      form.append("source_url", $("gitUrl").value.trim());
      const branch = $("gitBranch").value.trim();
      if (branch) form.append("source_branch", branch);
    }
    if (createDraft?.parentId) {
      form.append("parent_task_id", createDraft.parentId);
      form.append("action", createDraft.action || "retry");
    }
    files.forEach((file) => form.append("attachments", file));
    try {
      await api.ensureSession();
      const task = await api.apiForm("/api/v1/tasks", form);
      resetCreateForm();
      showCreate(false);
      await refresh();
      selectTask(task.id);
    } catch (e) {
      alert(e.message);
    }
  };

  $("renameBtn").onclick = async () => {
    if (!selected) return;
    const t = currentTask();
    const next = prompt("任务名称（留空清除自定义名）:", t?.name || "") ?? null;
    if (next === null) return;
    try {
      await api.api(`/api/v1/tasks/${selected}`, {
        method: "PATCH",
        body: JSON.stringify({ name: next }),
      });
      await refresh();
      selectTask(selected);
    } catch (e) {
      alert(e.message);
    }
  };

  $("saveNotesBtn").onclick = async () => {
    if (!selected) return;
    try {
      await api.api(`/api/v1/tasks/${selected}`, {
        method: "PATCH",
        body: JSON.stringify({ notes: $("overviewNotes").value }),
      });
      await refresh();
    } catch (e) {
      alert(e.message);
    }
  };

  $("holdBtn").onclick = async () => {
    if (!selected) return;
    try {
      await api.api(`/api/v1/tasks/${selected}/hold`, { method: "POST" });
      await refresh();
      selectTask(selected);
    } catch (e) {
      alert(e.message);
    }
  };

  $("releaseBtn").onclick = async () => {
    if (!selected) return;
    try {
      await api.api(`/api/v1/tasks/${selected}/release`, { method: "POST" });
      await refresh();
      selectTask(selected);
    } catch (e) {
      alert(e.message);
    }
  };

  $("retryBtn").onclick = () => {
    const t = currentTask();
    if (!t) return;
    showImport(false);
    fillCreateFormFromTask(t, "retry");
    showCreate(true);
  };

  function openInstructionModal(options) {
    const opts = options || {};
    return new Promise((resolve) => {
      const modal = $("instructionModal");
      const input = $("instructionModalInput");
      const confirmBtn = $("instructionModalConfirm");
      const cancelBtn = $("instructionModalCancel");
      const backdrop = $("instructionModalBackdrop");

      $("instructionModalTitle").textContent = opts.title || "附加指令";
      $("instructionModalSub").textContent = opts.sub || "";
      $("instructionModalLabel").textContent = opts.label || "附加指令";
      input.placeholder = opts.placeholder || "";
      confirmBtn.textContent = opts.confirmLabel || "确认";
      input.value = opts.initialValue || "";

      const close = (value) => {
        modal.classList.add("hidden");
        document.removeEventListener("keydown", onKey);
        confirmBtn.onclick = null;
        cancelBtn.onclick = null;
        backdrop.onclick = null;
        resolve(value);
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          close(null);
        } else if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
          e.preventDefault();
          close(input.value);
        }
      };

      modal.classList.remove("hidden");
      document.addEventListener("keydown", onKey);
      confirmBtn.onclick = () => close(input.value);
      cancelBtn.onclick = () => close(null);
      backdrop.onclick = () => close(null);
      setTimeout(() => input.focus(), 0);
    });
  }

  $("resumeBtn").onclick = async () => {
    if (!selected) return;
    const note = await openInstructionModal({
      title: "继续扫描",
      sub: "在同一 run 上续跑。附加指令可选，会作为本次 resume 的 nudge 交给 Agent。",
      label: "附加指令",
      placeholder: "例如：继续验证 SQL 注入；优先看认证绕过…",
      confirmLabel: "开始 Resume",
    });
    if (note === null) return;
    try {
      const body = note.trim() ? { instruction: note.trim() } : {};
      const t = await api.api(`/api/v1/tasks/${selected}/resume`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      await refresh();
      selectTask(t.id);
    } catch (e) {
      alert(e.message);
    }
  };

  $("retestBtn").onclick = async () => {
    if (!selected) return;
    const note = await openInstructionModal({
      title: "复测",
      sub: "将创建复测子任务，逐条验证漏洞是否修复并要求截图/佐证。凭证过期、新账号、环境变更等信息请写在下面，会一并交给 Agent。",
      label: "复测说明（凭证 / 环境）",
      placeholder:
        "例如：\n登录账号 admin / 新密码 xxx\nCookie: session=...\n目标仍是 https://example.com，忽略证书错误",
      confirmLabel: "开始复测",
    });
    if (note === null) return;
    try {
      const body = note.trim() ? { instruction: note.trim() } : {};
      const t = await api.api(`/api/v1/tasks/${selected}/retest`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      await refresh();
      selectTask(t.id);
    } catch (e) {
      alert(e.message);
    }
  };

  $("refreshReportBtn").onclick = async () => {
    if (!selected) return;
    const t = currentTask();
    const hint =
      t && TERMINAL.has(t.status)
        ? "将 resume 当前任务，按交付规范重写 finish_scan 报告（不扩测）。继续？"
        : "将向运行中的 Agent 发送「更新报告」指令。继续？";
    if (!confirm(hint)) return;
    try {
      const updated = await api.api(`/api/v1/tasks/${selected}/refresh-report`, {
        method: "POST",
      });
      await refresh();
      selectTask(updated.id);
      setTab("viewer");
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

  $("deleteBtn").onclick = async () => {
    if (!selected) return;
    const t = currentTask();
    if (!t || !DELETABLE.has(t.status)) {
      return alert("只能删除已结束或挂起的任务");
    }
    if (!confirm(`确认删除任务 ${selected}？将同时删除磁盘上的 workspace。`)) return;
    try {
      await api.api(`/api/v1/tasks/${selected}`, { method: "DELETE" });
      selected = null;
      viewerLoadedFor = null;
      selectedFindingId = null;
      findingsCache = [];
      $("detailPanel").classList.add("hidden");
      $("emptyState").classList.remove("hidden");
      await refresh();
    } catch (e) {
      alert(e.message);
    }
  };

  $("runImport").onclick = async () => {
    const path = $("importPath").value.trim();
    if (!path) return alert("请填写路径");
    const body = {
      path,
      dry_run: $("importDryRun").checked,
      skip_existing: $("importSkipExisting").checked,
    };
    try {
      await api.ensureSession();
      const result = await api.api("/api/v1/tasks/import", {
        method: "POST",
        body: JSON.stringify(body),
      });
      const lines = [
        `path: ${result.path}`,
        `dry_run: ${result.dry_run}`,
        `imported: ${result.imported_count}`,
        `skipped: ${result.skipped_count}`,
        "",
      ];
      (result.imported || []).forEach((item) => {
        lines.push(
          `+ ${item.run_name} → ${item.task_id || "(preview)"} [${item.status}] ${item.target || ""}`
        );
      });
      (result.skipped || []).forEach((item) => {
        lines.push(`- ${item.run_name}: ${item.reason || "skipped"}`);
      });
      $("importResult").textContent = lines.join("\n");
      $("importResult").classList.remove("hidden");
      if (!result.dry_run && result.imported_count > 0) {
        await refresh();
        const first = (result.imported || []).find((i) => i.task_id);
        if (first) {
          showImport(false);
          selectTask(first.task_id);
        }
      }
    } catch (e) {
      $("importResult").textContent = e.message;
      $("importResult").classList.remove("hidden");
    }
  };

  $("downloadReport").onclick = async () => {
    if (!selected) return;
    try {
      await api.ensureSession();
      const key = api.getKey();
      const res = await fetch(
        `/api/v1/tasks/${encodeURIComponent(selected)}/report?download=1`,
        {
          credentials: "include",
          headers: key ? { Authorization: `Bearer ${key}` } : {},
        }
      );
      if (!res.ok) {
        let msg = res.statusText;
        try {
          const data = await res.json();
          msg = (data && data.error && data.error.message) || msg;
        } catch {
          /* ignore */
        }
        throw new Error(msg);
      }
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `${selected}-report.zip`;
      a.click();
      URL.revokeObjectURL(a.href);
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
