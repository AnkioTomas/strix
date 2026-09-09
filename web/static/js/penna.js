/* Penna Markdown read-only renderer helpers (CDN IIFE). */
(function (global) {
  const PENNA_VER = "0.2.5";

  function createRenderer(mount) {
    if (!global.PennaNextRenderer) {
      throw new Error("Penna renderer not loaded");
    }
    const { Renderer, Theme, EventBus, Log } = global.PennaNextRenderer;
    mount.classList.add("penna-render");
    const log = new Log(false);
    const eventBus = new EventBus(false, "[strix-penna]", log);
    const root = mount.parentElement || mount;
    const theme = new Theme(eventBus, log, root);
    const renderer = new Renderer({ mount, theme, eventBus, logger: log });
    try {
      theme.setTheme("github");
    } catch (_) {
      /* default theme if github skin missing */
    }
    return renderer;
  }

  /** Rewrite relative image/file links to same-origin artifact URLs. */
  function rewriteArtifactLinks(markdown, taskId) {
    if (!taskId) return String(markdown || "");
    return String(markdown || "").replace(
      /(!?\[[^\]]*\]\()([^)\s]+)(\))/g,
      (full, open, src, close) => {
        const url = src.trim();
        if (/^https?:\/\//i.test(url) || url.startsWith("/api/") || url.startsWith("data:")) {
          return full;
        }
        const clean = url.replace(/^(\.\/)+/, "").replace(/^\/+/, "");
        const proxied =
          `/api/v1/tasks/${encodeURIComponent(taskId)}/artifacts/` +
          clean.split("/").map(encodeURIComponent).join("/");
        return open + proxied + close;
      }
    );
  }

  function alertForSeverity(severity) {
    const s = String(severity || "").toLowerCase();
    if (s === "critical" || s === "high") return "CAUTION";
    if (s === "medium") return "WARNING";
    if (s === "low") return "NOTE";
    return "TIP";
  }

  function findingsToMarkdown(findings) {
    const rows = findings || [];
    if (!rows.length) {
      return "> [!NOTE]\n> 该任务暂无漏洞。\n";
    }
    const parts = [`# 漏洞清单\n\n共 **${rows.length}** 条。\n`];
    rows.forEach((f, i) => {
      const loc = f.location || {};
      const where = loc.file
        ? `${loc.file}${loc.line != null ? `:${loc.line}` : ""}`
        : loc.url || loc.endpoint || loc.parameter || "—";
      const alert = alertForSeverity(f.severity);
      parts.push(`## ${i + 1}. ${f.title || "Untitled"}\n`);
      parts.push(`> [!${alert}]\n> **${(f.severity || "unknown").toUpperCase()}**` +
        (f.confidence ? ` · confidence: ${f.confidence}` : "") + "\n");
      parts.push("");
      parts.push(`| 字段 | 内容 |`);
      parts.push(`| --- | --- |`);
      parts.push(`| 资产 | ${f.asset || "—"} |`);
      parts.push(`| 位置 | ${where} |`);
      if (f.cwe) parts.push(`| CWE | ${f.cwe} |`);
      if (f.cvss != null) parts.push(`| CVSS | ${f.cvss} |`);
      parts.push("");
      if (f.description) {
        parts.push("### 描述\n");
        parts.push(String(f.description).trim());
        parts.push("");
      }
      if (f.evidence) {
        parts.push("### 证据\n");
        parts.push("```\n" + String(f.evidence).trim() + "\n```\n");
      }
      if (f.poc) {
        parts.push("### PoC\n");
        parts.push("```\n" + String(f.poc).trim() + "\n```\n");
      }
      if (f.impact) {
        parts.push("### 影响\n");
        parts.push(String(f.impact).trim());
        parts.push("");
      }
      if (f.recommendation) {
        parts.push("### 修复建议\n");
        parts.push(String(f.recommendation).trim());
        parts.push("");
      }
      parts.push("---\n");
    });
    return parts.join("\n");
  }

  global.StrixPenna = {
    PENNA_VER,
    createRenderer,
    rewriteArtifactLinks,
    findingsToMarkdown,
  };
})(window);
