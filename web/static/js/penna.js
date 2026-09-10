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

  function locationLabel(f) {
    const loc = (f && f.location) || {};
    if (loc.file) return `${loc.file}${loc.line != null ? `:${loc.line}` : ""}`;
    return loc.url || loc.endpoint || loc.parameter || f.asset || "—";
  }

  function findingToMarkdown(f) {
    if (!f) {
      return "> [!NOTE]\n> 未找到该漏洞。\n";
    }
    const where = locationLabel(f);
    const alert = alertForSeverity(f.severity);
    const parts = [];
    parts.push(`# ${f.title || "Untitled"}\n`);
    parts.push(
      `> [!${alert}]\n> **${(f.severity || "unknown").toUpperCase()}**` +
        (f.confidence ? ` · confidence: ${f.confidence}` : "") +
        "\n"
    );
    parts.push("");
    parts.push(`| 字段 | 内容 |`);
    parts.push(`| --- | --- |`);
    parts.push(`| ID | \`${f.id || "—"}\` |`);
    parts.push(`| 资产 | ${f.asset || "—"} |`);
    parts.push(`| 位置 | ${where} |`);
    if (f.cwe) parts.push(`| CWE | ${f.cwe} |`);
    if (f.cvss != null) parts.push(`| CVSS | ${f.cvss} |`);
    parts.push("");
    if (f.description) {
      parts.push("## 描述\n");
      parts.push(String(f.description).trim());
      parts.push("");
    }
    if (f.technical_analysis) {
      parts.push("## 技术分析\n");
      parts.push(String(f.technical_analysis).trim());
      parts.push("");
    }
    if (f.evidence) {
      parts.push("## 证据\n");
      parts.push("```\n" + String(f.evidence).trim() + "\n```\n");
    }
    if (f.poc) {
      parts.push("## PoC\n");
      parts.push(String(f.poc).trim());
      parts.push("");
    }
    const shots = Array.isArray(f.screenshots) ? f.screenshots : [];
    if (shots.length) {
      parts.push("## 截图\n");
      shots.forEach((src, i) => {
        parts.push(`![screenshot ${i + 1}](${String(src).trim()})`);
        parts.push("");
      });
    }
    if (f.impact) {
      parts.push("## 影响\n");
      parts.push(String(f.impact).trim());
      parts.push("");
    }
    if (f.recommendation) {
      parts.push("## 修复建议\n");
      parts.push(String(f.recommendation).trim());
      parts.push("");
    }
    return parts.join("\n");
  }

  function findingsToMarkdown(findings) {
    const rows = findings || [];
    if (!rows.length) {
      return "> [!NOTE]\n> 该任务暂无漏洞。\n";
    }
    const parts = [`# 漏洞清单\n\n共 **${rows.length}** 条。\n`];
    rows.forEach((f) => {
      parts.push(findingToMarkdown(f));
      parts.push("\n---\n");
    });
    return parts.join("\n");
  }

  global.StrixPenna = {
    PENNA_VER,
    createRenderer,
    rewriteArtifactLinks,
    locationLabel,
    findingToMarkdown,
    findingsToMarkdown,
  };
})(window);
