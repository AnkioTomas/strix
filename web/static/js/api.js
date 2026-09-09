/* Shared API helpers for the console. */
(function (global) {
  const KEY_STORAGE = "strix_api_key";

  function getKey() {
    const input = document.getElementById("apiKey");
    return (localStorage.getItem(KEY_STORAGE) || (input && input.value) || "").trim();
  }

  function setKey(value) {
    localStorage.setItem(KEY_STORAGE, value.trim());
    const input = document.getElementById("apiKey");
    if (input) input.value = value.trim();
  }

  function headers(extra) {
    const h = Object.assign({ "Content-Type": "application/json" }, extra || {});
    const key = getKey();
    if (key) h.Authorization = `Bearer ${key}`;
    return h;
  }

  async function api(path, opts) {
    opts = opts || {};
    const res = await fetch(path, {
      ...opts,
      credentials: "include",
      headers: { ...headers(), ...(opts.headers || {}) },
    });
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      const msg = (data && data.error && data.error.message) || res.statusText;
      throw new Error(msg);
    }
    return data;
  }

  async function ensureSession() {
    const key = getKey();
    if (!key) return false;
    const res = await fetch("/api/v1/session", {
      method: "POST",
      credentials: "include",
      headers: headers(),
    });
    if (!res.ok && res.status !== 204) {
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch { /* ignore */ }
      throw new Error((data && data.error && data.error.message) || res.statusText);
    }
    return true;
  }

  async function clearSession() {
    await fetch("/api/v1/session", { method: "DELETE", credentials: "include" });
    localStorage.removeItem(KEY_STORAGE);
    const input = document.getElementById("apiKey");
    if (input) input.value = "";
  }

  global.StrixAPI = { getKey, setKey, headers, api, ensureSession, clearSession, KEY_STORAGE };
})(window);
