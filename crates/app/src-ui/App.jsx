import React, { useCallback, useEffect, useRef, useState } from "react";
import Button from "@brave/leo/react/button";
import Input from "@brave/leo/react/input";
import Dropdown from "@brave/leo/react/dropdown";
import Checkbox from "@brave/leo/react/checkbox";
import Icon from "@brave/leo/react/icon";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const clipboard = window.__TAURI__.clipboardManager;

// ---------- Tauri helpers ----------
async function copyText(text, what, setToast) {
  try { await clipboard.writeText(text); setToast(`${what} copied`); }
  catch { setToast("Copy failed"); }
}
async function openExternal(url) {
  try {
    if (window.__TAURI__.opener?.openUrl) await window.__TAURI__.opener.openUrl(url);
    else await invoke("plugin:opener|open_url", { url });
  } catch (e) { /* ignore */ }
}

const NAV = [
  { view: "all", label: "All Items", icon: "grid04" },
  { view: "favorites", label: "Favorites", icon: "star-outline" },
  { view: "passwords", label: "Passwords", icon: "key" },
  { view: "identities", label: "Identities", icon: "user" },
  { view: "bookmarks", label: "Bookmarks", icon: "product-bookmarks" },
  { view: "reading", label: "Reading List", icon: "reading-list-add" },
  { view: "tabgroups", label: "Tab Groups", icon: "browser-group" },
  { view: "opentabs", label: "Open Tabs", icon: "window-tabs" },
  { view: "devices", label: "Devices", icon: "laptop" },
];

const PALETTE = ["#e06c75","#98c379","#61afef","#c678dd","#e5c07b","#56b6c2","#d19a66","#be5046","#7e57c2","#26a69a"];
function colorFor(s) {
  let h = 2166136261;
  for (const ch of (s || "").toLowerCase()) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); }
  return PALETTE[Math.abs(h) % PALETTE.length];
}

// ================= App =================
export default function App() {
  const [screen, setScreen] = useState("unlock"); // unlock | setup | main
  const [toast, setToast] = useState("");
  const toastTimer = useRef(null);
  const showToast = useCallback((msg) => {
    setToast(msg);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(""), 1800);
  }, []);

  return (
    <>
      <div className="titlebar-drag" data-tauri-drag-region />
      {screen === "unlock" && <Unlock setScreen={setScreen} />}
      {screen === "setup" && <Setup setScreen={setScreen} />}
      {screen === "main" && <Main setScreen={setScreen} showToast={showToast} />}
      {toast && <div className="toast">{toast}</div>}
    </>
  );
}

// ---------- Unlock ----------
function Unlock({ setScreen }) {
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const inputRef = useRef(null);
  useEffect(() => {
    invoke("has_config").then((ok) => { if (!ok) setErr("BRAVE_SERVICES_KEY not set. Launch with it configured."); });
    const t = setTimeout(() => { try { inputRef.current?.focus?.(); } catch {} }, 60);
    return () => clearTimeout(t);
  }, []);
  const submit = async () => {
    const ok = await invoke("unlock", { password: pw });
    if (!ok) { setErr("Wrong password"); return; }
    setScreen((await invoke("has_chain")) ? "main" : "setup");
  };
  return (
    <div className="screen center">
      <div className="card">
        <img className="brand-mark" src="/brave-logo.svg" alt="Brave" />
        <h1>Brave Vault</h1>
        <p className="muted">Enter your vault password to unlock</p>
        <Input ref={inputRef} type="password" placeholder="Password" value={pw}
          onInput={(e) => setPw(e.value)} onKeyDown={(e) => { if (e.key === "Enter") submit(); }} />
        <Button onClick={submit}>Unlock</Button>
        {err && <div className="error">{err}</div>}
      </div>
    </div>
  );
}

// ---------- Setup ----------
function Setup({ setScreen }) {
  const [code, setCode] = useState("");
  const [gen, setGen] = useState("");
  const [err, setErr] = useState("");
  const join = async () => {
    try { await invoke("join_chain", { code: code.trim() }); setScreen("main"); }
    catch (e) { setErr("Invalid sync code: " + e); }
  };
  const generate = async () => {
    try { setGen(await invoke("generate_chain")); } catch (e) { setErr(String(e)); }
  };
  return (
    <div className="screen center">
      <div className="card setup">
        <h1>Set up sync</h1>
        <p className="muted">Join your Brave sync chain, or create a new one.</p>
        <label>Paste your Brave sync code</label>
        <Input placeholder="word1 word2 … word24" value={code} onInput={(e) => setCode(e.value)} />
        <Button onClick={join}>Join chain</Button>
        <div className="divider"><span>or</span></div>
        <Button kind="outline" onClick={generate}>Generate a new chain</Button>
        {gen && (<><label>Your new sync code — write it down</label><div className="code-box">{gen}</div></>)}
        {err && <div className="error">{err}</div>}
      </div>
    </div>
  );
}

// Draggable column widths for the sidebar + list panes, persisted to localStorage.
function useResizableColumns() {
  const layoutRef = useRef(null);
  const COLS = {
    1: { min: 160, max: 360, def: 210, css: "--col-sidebar", key: "col-sidebar" },
    2: { min: 240, max: 600, def: 340, css: "--col-list", key: "col-list" },
  };
  useEffect(() => {
    const el = layoutRef.current;
    if (!el) return;
    for (const c of Object.values(COLS)) {
      const v = parseInt(localStorage.getItem(c.key) || "", 10);
      if (v) el.style.setProperty(c.css, v + "px");
    }
  }, []);
  const startDrag = (which) => (e) => {
    e.preventDefault();
    const el = layoutRef.current, conf = COLS[which];
    const startX = e.clientX;
    const startW = parseInt(getComputedStyle(el).getPropertyValue(conf.css), 10) || conf.def;
    e.currentTarget.classList.add("dragging");
    const handle = e.currentTarget;
    const onMove = (ev) => {
      const w = Math.max(conf.min, Math.min(conf.max, startW + (ev.clientX - startX)));
      el.style.setProperty(conf.css, w + "px");
    };
    const onUp = () => {
      handle.classList.remove("dragging");
      localStorage.setItem(conf.key, String(parseInt(getComputedStyle(el).getPropertyValue(conf.css), 10) || conf.def));
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
    };
    document.body.style.cursor = "col-resize";
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  };
  return { layoutRef, startDrag };
}

// ---------- Main ----------
function Main({ setScreen, showToast }) {
  const { layoutRef, startDrag } = useResizableColumns();
  const [view, setView] = useState("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState("name");
  const [filter, setFilter] = useState("");
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(null);
  const [editing, setEditing] = useState(null); // {mode:'new'|'edit'|'newbookmark'|'newidentity', item}
  const [syncStatus, setSyncStatus] = useState("");
  const [folderStack, setFolderStack] = useState([]);
  const [total, setTotal] = useState(0);
  const favCache = useRef(new Map());
  const [genOpen, setGenOpen] = useState(false);
  const [ctx, setCtx] = useState(null); // {x,y,item}
  const [savingId, setSavingId] = useState(null);
  const [purging, setPurging] = useState(false); // bulk purge running (shows Cancel)
  const [busy, setBusy] = useState(false);        // any device op running (shows spinner)
  const [purgeMsg, setPurgeMsg] = useState("");
  const reqSeq = useRef(0);

  const folder = folderStack.length ? folderStack[folderStack.length - 1].guid : "";
  const isPwView = view === "all" || view === "passwords" || view === "favorites";

  const refresh = useCallback(async (opts = {}) => {
    const v = opts.view ?? view, q = opts.query ?? query, s = opts.sort ?? sort;
    const f = opts.filter ?? filter, fol = opts.folder ?? folder;
    const seq = ++reqSeq.current;
    const t = setTimeout(() => { if (seq === reqSeq.current) setLoading(true); }, 120);
    const rows = await invoke("list_items", { view: v, query: q, folder: fol, sort: s, filter: f });
    clearTimeout(t);
    if (seq !== reqSeq.current) return;
    setLoading(false);
    setItems(rows);
    // Fill favicons lazily.
    const need = [...new Set(rows.map((r) => r.favkey).filter((k) => k && !favCache.current.has(k)))];
    if (need.length) {
      const map = await invoke("favicons", { hosts: need });
      for (const [h, u] of Object.entries(map)) favCache.current.set(h, u);
      for (const h of need) if (!favCache.current.has(h)) favCache.current.set(h, "");
      setItems((cur) => [...cur]); // re-render with icons
    }
  }, [view, query, sort, filter, folder]);

  const doSync = useCallback(async (opts = {}) => {
    // quiet: reconcile in the background after an optimistic mutation — don't
    // flash a blocking status or surface errors as toasts (the mutation handler
    // already did). Loud: the initial load / explicit Sync button.
    const quiet = opts.quiet === true;
    if (!quiet) setSyncStatus("Syncing…");
    try {
      const r = await invoke("sync");
      setSyncStatus(r.pending_count > 0
        ? `Syncing ${r.pending_count} pending change${r.pending_count > 1 ? "s" : ""}…`
        : `${r.password_count} passwords · ${r.bookmark_count} bookmarks`);
      await refresh();
      invoke("fetch_favicons").then((n) => { if (n > 0) { favCache.current.clear(); refresh(); } });
    } catch (e) {
      if (!quiet) { setSyncStatus("Sync failed"); showToast("Sync failed: " + e); }
    }
  }, [refresh, showToast]);

  // Fire a mutation optimistically: the caller has already updated the local
  // view, so we just run the network commit + a quiet reconciling sync in the
  // background and report success/failure without ever blocking the UI.
  const runInBackground = useCallback((commit, { ok, fail }) => {
    (async () => {
      try {
        await commit();
        if (ok) showToast(ok);
      } catch (e) {
        showToast((fail || "Failed") + ": " + e);
      }
      // Reconcile with the server regardless (confirms our write or rolls the
      // optimistic view back to the authoritative state).
      doSync({ quiet: true });
    })();
  }, [doSync, showToast]);

  // Initial load: show cached data, flush any mutations left over from a
  // previous run (closed mid-commit), then sync.
  useEffect(() => {
    (async () => {
      await refresh();
      try {
        const flushed = await invoke("replay_outbox");
        if (flushed > 0) showToast(`Synced ${flushed} pending change${flushed > 1 ? "s" : ""}`);
      } catch { /* stays queued for next launch */ }
      doSync();
    })();
    /* eslint-disable-next-line */
  }, []);
  // Re-list whenever view controls change.
  useEffect(() => { refresh(); /* eslint-disable-next-line */ }, [view, query, sort, filter, folder]);
  // Close context menu on any click.
  useEffect(() => {
    const close = () => setCtx(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  const changeView = (v) => {
    setView(v); setQuery(""); setFilter(""); setFolderStack([]); setSelected(null); setEditing(null);
  };

  const toggleFav = (item) => {
    // Local-only preference — flip instantly, persist in the background.
    const nowFav = !item.favorite;
    setItems((cur) => view === "favorites" && !nowFav
      ? cur.filter((r) => r.uid !== item.uid)           // dropped from the favorites list
      : cur.map((r) => r.uid === item.uid ? { ...r, favorite: nowFav } : r));
    if (selected && selected.uid === item.uid) setSelected({ ...selected, favorite: nowFav });
    invoke("toggle_favorite", { id: item.id }).catch((e) => showToast("Favorite failed: " + e));
  };

  const del = (item) => {
    if (!confirm(`Delete "${item.title || item.url}"? This removes it from every device on the chain.`)) return;
    // Optimistic: drop the row and clear the detail pane immediately.
    setItems((cur) => cur.filter((r) => r.uid !== item.uid));
    setSelected(null); setEditing(null);
    runInBackground(() => invoke("delete_item", { id: item.id }), { ok: "Deleted", fail: "Delete failed" });
  };

  const removeDevice = async (item) => {
    if (busy) return;
    // Reuse the purge status row + spinner for single-device removal. No
    // window.confirm() (it silently returns false inside the webview); the
    // device re-appears on next sync if it's still active, so this is safe.
    setBusy(true);
    setPurgeMsg(`Removing ${item.title}…`);
    try {
      await invoke("delete_device", { cacheGuid: item.guid });
      setItems((cur) => cur.filter((r) => r.uid !== item.uid));
      setPurgeMsg(`Removed ${item.title}`);
      showToast("Device removed");
      doSync({ quiet: true });
    } catch (e) {
      setPurgeMsg("Remove failed: " + e);
      showToast("Remove failed: " + e);
    } finally {
      setBusy(false);
      setTimeout(() => setPurgeMsg(""), 8000);
    }
  };

  // Live progress streamed from the backend during a purge (device fetched /
  // each removal), so the status line mirrors what the logs show.
  useEffect(() => {
    let unlisten;
    listen("purge-progress", (e) => {
      const p = e.payload || {};
      if (p.phase === "fetched") {
        setPurgeMsg(p.stale > 0
          ? `Found ${p.total} devices — removing ${p.stale} stale…`
          : `Found ${p.total} devices — none are stale`);
      } else if (p.phase === "removing") {
        setPurgeMsg(`Removing ${p.name} (${p.index} of ${p.stale})…`);
      }
    }).then((u) => { unlisten = u; });
    return () => { if (unlisten) unlisten(); };
  }, []);

  const purgeStaleDevices = async () => {
    if (busy) return;
    const days = 30;
    // One click starts it (Cancel button appears while it runs). The backend
    // streams purge-progress events that drive the status line above.
    setPurging(true);
    setBusy(true);
    setPurgeMsg("Fetching device list from sync server…");
    try {
      const removed = await invoke("purge_stale_devices", { days });
      const msg = removed.length > 0
        ? `Removed ${removed.length} device${removed.length > 1 ? "s" : ""}: ${removed.join(", ")}`
        : "Done — no devices were stale (none older than 30 days)";
      setPurgeMsg(msg);
      showToast(removed.length > 0
        ? `Removed ${removed.length} stale device${removed.length > 1 ? "s" : ""}`
        : "No stale devices found");
      await refresh();
    } catch (e) {
      const msg = "Purge failed: " + e;
      setPurgeMsg(msg);
      showToast(msg);
    } finally {
      setPurging(false);
      setBusy(false);
      setTimeout(() => setPurgeMsg(""), 8000);
    }
  };

  const cancelPurge = () => {
    invoke("cancel_purge").catch(() => {});
    setPurgeMsg("Cancelling…");
  };

  const saveItem = async (args, uid) => {
    // Optimistic: patch the edited row in place (or just close for a new item),
    // then commit + reconcile in the background.
    if (uid) {
      setItems((cur) => cur.map((r) => r.uid === uid
        ? { ...r, title: args.title, username: args.username, password: args.password, subtitle: args.username, notes: args.notes }
        : r));
    }
    setEditing(null); setSelected(null);
    runInBackground(() => invoke("save_item", { args }), { ok: "Saved", fail: "Save failed" });
  };

  const saveBookmark = async (args) => {
    setEditing(null); setSelected(null);
    runInBackground(() => invoke("save_bookmark", { args }), { ok: "Saved", fail: "Save failed" });
  };

  const saveIdentity = async (args) => {
    setEditing(null); setSelected(null);
    runInBackground(() => invoke("save_identity", { args }), { ok: "Saved", fail: "Save failed" });
  };

  const filterOptions = view === "bookmarks"
    ? [["", "All bookmarks"], ["dupes", "⧉ Duplicate bookmarks"]]
    : isPwView
    ? [["", "All items"], ["weak", "⚠ Weak passwords"], ["reused", "⧉ Reused passwords"], ["conflict", "⚔ Mismatched passwords"]]
    : null;

  return (
    <div className="layout" ref={layoutRef}>
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-title" data-tauri-drag-region>Brave Vault</div>
        <nav>
          {NAV.map((n) => (
            <button key={n.view} className={"nav-item" + (view === n.view ? " active" : "")}
              onClick={() => changeView(n.view)}>
              <span className={"nav-ico" + (n.view === "favorites" ? " star" : "")}><Icon name={n.icon} /></span>
              {n.label}
              {n.view === "all" && total ? <span className="nav-count">{total}</span> : null}
            </button>
          ))}
        </nav>
        <div className="sidebar-sep" />
        <button className="nav-item" onClick={() => setGenOpen(true)}><span className="nav-ico"><Icon name="settings" /></span> Generator</button>
        <div className="sidebar-spacer" />
        {syncStatus && <div className="sync-status">{syncStatus}</div>}
        <div className="sidebar-actions">
          <Button size="small" kind="outline" onClick={() => doSync()}>Sync</Button>
          <Button size="small" kind="outline" onClick={async () => { await invoke("lock"); setScreen("unlock"); }}>Lock</Button>
        </div>
      </aside>

      <div className="resizer" onMouseDown={startDrag(1)} />

      {/* List column */}
      <div className="list-col">
        <div className="list-header">
          <Input className="search" placeholder="Search" value={query} onInput={(e) => setQuery(e.value)}>
            <Icon name="search" slot="left-icon" />
          </Input>
          {(isPwView || view === "bookmarks" || view === "identities") && (
            <Button size="small" onClick={() => {
              setSelected(null);
              if (view === "bookmarks") setEditing({ mode: "newbookmark" });
              else if (view === "identities") setEditing({ mode: "newidentity" });
              else setEditing({ mode: "new" });
            }}><Icon name="plus-add" slot="icon-before" />New</Button>
          )}
          {view === "devices" && !purging && (
            <Button size="small" kind="outline" onClick={purgeStaleDevices}>
              <Icon name="trash" slot="icon-before" />Purge stale
            </Button>
          )}
          {view === "devices" && purging && (
            <Button size="small" kind="outline" onClick={cancelPurge}>
              Cancel purge
            </Button>
          )}
        </div>
        {view === "devices" && purgeMsg && (
          <div className="purge-status">
            {busy && <span className="spinner" />}
            <span>{purgeMsg}</span>
          </div>
        )}
        {(isPwView || view === "bookmarks") && (
          <div className="toolbar">
            {isPwView && (
              <Dropdown className="mini" value={sort} onChange={(e) => setSort(e.value)}>
                <span slot="value">{{ name: "Name", created: "Recently added", used: "Recently used", modified: "Recently updated", weakest: "Weakest first" }[sort]}</span>
                <leo-option value="name">Name</leo-option>
                <leo-option value="created">Recently added</leo-option>
                <leo-option value="used">Recently used</leo-option>
                <leo-option value="modified">Recently updated</leo-option>
                <leo-option value="weakest">Weakest first</leo-option>
              </Dropdown>
            )}
            {filterOptions && (
              <Dropdown className="mini" value={filter} onChange={(e) => setFilter(e.value)}>
                <span slot="value">{filterOptions.find(([v]) => v === filter)?.[1] || filterOptions[0][1]}</span>
                {filterOptions.map(([v, label]) => <leo-option key={v} value={v}>{label}</leo-option>)}
              </Dropdown>
            )}
          </div>
        )}
        {view === "bookmarks" && folderStack.length > 0 && (
          <div className="crumb" onClick={() => setFolderStack((s) => s.slice(0, -1))}>
            ‹ {folderStack.map((f) => f.title).join(" / ")}
          </div>
        )}
        <ItemList items={items} loading={loading} selected={selected} savingId={savingId}
          favCache={favCache.current} view={view} query={query} filter={filter}
          onSelect={(it) => { setSelected(it); setEditing(null); }}
          onOpenFolder={(it) => setFolderStack((s) => [...s, { guid: it.guid, title: it.title }])}
          onToggleFav={toggleFav}
          onRemoveDevice={removeDevice}
          onContext={(e, it) => { e.preventDefault(); setCtx({ x: e.clientX, y: e.clientY, item: it }); }} />
      </div>

      <div className="resizer" onMouseDown={startDrag(2)} />

      {/* Detail column */}
      <div className="detail">
        {editing
          ? <EditPane editing={editing} folder={folder} onCancel={() => setEditing(null)}
              onSave={saveItem} onSaveBookmark={saveBookmark} onSaveIdentity={saveIdentity}
              onDelete={del} showToast={showToast} savingId={savingId} />
          : selected
          ? <DetailPane item={selected} onEdit={() => setEditing({ mode: "edit", item: selected })}
              onToggleFav={toggleFav} onDelete={del} showToast={showToast} favCache={favCache.current}
              onSelect={(it) => setSelected(it)} />
          : <div className="detail-empty muted">Select an item</div>}
      </div>

      {ctx && (
        <div className="ctx-menu" style={{ left: ctx.x, top: ctx.y }}>
          <button onClick={() => { const it = ctx.item; setCtx(null); duplicate(it, view, setEditing); }}>Duplicate this item</button>
        </div>
      )}

      {genOpen && <GeneratorModal onClose={() => setGenOpen(false)} showToast={showToast} />}
    </div>
  );
}

function duplicate(item, view, setEditing) {
  if (item.kind === "password") setEditing({ mode: "new", prefill: { title: (item.title || "") + " (copy)", username: item.username, password: item.password, url: item.url, notes: item.notes } });
  else if (item.kind === "bookmark") setEditing({ mode: "newbookmark", prefill: { title: (item.title || "") + " (copy)", url: item.url } });
  else if (item.kind === "identity") {
    const f = {};
    for (const line of (item.notes || "").split("\n")) { const i = line.indexOf(": "); if (i > 0) f[line.slice(0, i).toLowerCase()] = line.slice(i + 2); }
    setEditing({ mode: "newidentity", prefill: { ...f, name: (f.name || "") + " (copy)" } });
  }
}

// ---------- Avatar ----------
function Avatar({ item, favCache, size = 34 }) {
  const uri = item.favicon || (item.favkey && favCache.get(item.favkey));
  const style = { width: size, height: size, borderRadius: size * 0.26 };
  if (item.kind === "folder") return <div className="avatar folder" style={style}><Icon name="folder" /></div>;
  if (item.kind === "device") {
    const sub = (item.subtitle || "").toLowerCase();
    const ic = sub.includes("phone") ? "smartphone" : sub.includes("desktop") ? "monitor" : "laptop";
    return <div className="avatar device" style={style}><Icon name={ic} /></div>;
  }
  if (uri) return <div className="avatar" style={{ ...style, background: "#fff" }}><img src={uri} alt="" /></div>;
  if (item.initials) return <div className="avatar" style={{ ...style, background: colorFor(item.title), fontSize: size / 2.4 }}>{item.initials}</div>;
  return <div className="avatar doc" style={style}><Icon name="window-content" /></div>;
}

// ---------- Item list ----------
function ItemList({ items, loading, selected, savingId, favCache, view, query, filter, onSelect, onOpenFolder, onToggleFav, onContext, onRemoveDevice }) {
  if (loading) return <div className="list"><div className="loading"><span className="spinner" />Loading…</div></div>;
  if (items.length === 0) {
    const fm = { weak: "No weak passwords 🎉", reused: "No reused passwords 🎉", conflict: "No mismatched passwords 🎉", dupes: "No duplicate bookmarks 🎉" };
    const msg = filter && fm[filter] ? fm[filter] : query ? "No matches."
      : view === "favorites" ? "No favorites yet." : view === "bookmarks" ? "This folder is empty." : "No items yet.";
    return <div className="list"><div className="empty-note">{msg}</div></div>;
  }
  return (
    <div className="list">
      {items.map((item) => {
        if (item.kind === "group") return <div key={item.uid} className="group-header">{item.title}</div>;
        const sel = selected && selected.uid === item.uid;
        const primary = item.title?.trim() ? item.title : item.subtitle;
        const secondary = item.title?.trim() ? item.subtitle : "";
        const isDevice = item.kind === "device";
        const editable = ["password", "bookmark", "identity"].includes(item.kind);
        return (
          <div key={item.uid} className={"list-row" + (sel ? " selected" : "") + (isDevice ? " static" : "")}
            onClick={isDevice ? undefined : () => item.kind === "folder" ? onOpenFolder(item) : onSelect(item)}
            onContextMenu={editable ? (e) => onContext(e, item) : undefined}>
            <Avatar item={item} favCache={favCache} />
            <div className="meta">
              <div className="title">{primary || "Untitled"}{item.favorite && <span className="fav-star"><Icon name="star-filled" /></span>}{item.pending && <span className="pending-dot" title="Syncing…" />}</div>
              {secondary && <div className="sub">{secondary}</div>}
            </div>
            {item.kind === "folder" && <div className="chev">›</div>}
            {savingId === item.uid && <span className="spinner" />}
            {editable && savingId !== item.uid && (
              <button className={"rowstar" + (item.favorite ? " on" : "")}
                onClick={(e) => { e.stopPropagation(); onToggleFav(item); }}><Icon name={item.favorite ? "star-filled" : "star-outline"} /></button>
            )}
            {isDevice && !item.current && savingId !== item.uid && (
              <button className="rowtrash" title="Remove from sync chain"
                onClick={(e) => { e.stopPropagation(); onRemoveDevice(item); }}><Icon name="trash" /></button>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------- Detail ----------
function DetailPane({ item, onEdit, onToggleFav, onDelete, showToast, favCache, onSelect }) {
  const [reveal, setReveal] = useState(false);
  const [related, setRelated] = useState([]);
  const editable = ["password", "bookmark", "identity"].includes(item.kind);
  useEffect(() => {
    setReveal(false); setRelated([]);
    if (item.kind === "password") invoke("related_items", { uid: item.uid }).then(setRelated);
  }, [item.uid]);

  return (
    <div className="detail-inner">
      <div className="detail-head">
        <Avatar item={item} favCache={favCache} size={48} />
        <div className="detail-headmeta">
          <div className="detail-title">{item.title || item.url || "Untitled"}</div>
          {(item.url || item.subtitle) && <div className="detail-realm">{item.url || item.subtitle}</div>}
        </div>
        <div className="actions">
          {editable && <Button fab size="small" kind="outline" title="Favorite" onClick={() => onToggleFav(item)}><Icon name={item.favorite ? "star-filled" : "star-outline"} /></Button>}
          {item.kind === "password" && <Button fab size="small" kind="outline" title="Edit" onClick={onEdit}><Icon name="edit-pencil" /></Button>}
          {editable && <Button fab size="small" kind="outline" title="Delete" onClick={() => onDelete(item)}><Icon name="trash" /></Button>}
        </div>
      </div>

      {item.kind === "identity"
        ? (item.notes || "").split("\n").filter((l) => l.includes(": ")).map((l, i) => {
            const idx = l.indexOf(": ");
            return <Field key={i} label={l.slice(0, idx)} value={l.slice(idx + 2)} showToast={showToast} />;
          })
        : <>
            {item.username && <Field label="Username" value={item.username} showToast={showToast} />}
            {item.password && <PasswordField item={item} reveal={reveal} setReveal={setReveal} showToast={showToast} />}
            {item.url && <UrlField url={item.url} />}
            {item.notes && item.kind !== "identity" && (
              <div className="field"><div className="field-label">Notes</div><div className="val" style={{ whiteSpace: "pre-wrap" }}>{item.notes}</div></div>
            )}
          </>}

      {related.length > 0 && (
        <div className="related">
          <div className="field-label">Related · same site ({related.length})</div>
          {related.map((r) => (
            <div key={r.uid} className="related-row" onClick={() => onSelect(r)}>
              <Avatar item={r} favCache={favCache} size={28} />
              <div className="meta">
                <div className="title">{r.username || r.title}</div>
                <div className="sub">{r.conflict ? "⚔ mismatched" : r.password === item.password ? "same password" : ""}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, value, showToast }) {
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div className="field-value">
        <div className="val grow">{value}</div>
        <Button size="tiny" kind="plain-faint" onClick={() => copyText(value, label, showToast)}>Copy</Button>
      </div>
    </div>
  );
}

function PasswordField({ item, reveal, setReveal, showToast }) {
  const color = item.strength < 40 ? "#e06c75" : item.strength < 70 ? "#e5c07b" : "#98c379";
  return (
    <div className="field">
      <div className="field-label">Password</div>
      <div className="field-value">
        <div className="val grow mono">{reveal ? item.password : "••••••••••••"}</div>
        <Button size="tiny" kind="plain-faint" onClick={() => setReveal(!reveal)}>{reveal ? "Hide" : "Reveal"}</Button>
        <Button size="tiny" kind="plain-faint" onClick={() => copyText(item.password, "Password", showToast)}>Copy</Button>
      </div>
      <div className="strength">
        <div className="bar"><div className="fill" style={{ width: item.strength + "%", background: color }} /></div>
        <div className="lbl">{item.strength_label}</div>
      </div>
    </div>
  );
}

function UrlField({ url }) {
  return (
    <div className="field">
      <div className="field-label">Website</div>
      <div className="field-value">
        <a className="val grow link" href="#" onClick={(e) => { e.preventDefault(); openExternal(url); }}>{url}</a>
        <Button size="tiny" kind="plain-faint" onClick={() => openExternal(url)}>Open</Button>
      </div>
    </div>
  );
}

// ---------- Edit / New ----------
function EditPane({ editing, folder, onCancel, onSave, onSaveBookmark, onSaveIdentity, onDelete, showToast, savingId }) {
  const { mode, item, prefill } = editing;
  const src = item || prefill || {};
  const [f, setF] = useState({
    title: src.title || "", username: src.username || "", password: src.password || "",
    url: src.url || "", notes: src.notes || "",
    name: src.name || "", email: src.email || "", phone: src.phone || "", company: src.company || "",
    street: src.street || "", city: src.city || "", state: src.state || "", zip: src.zip || "", country: src.country || "",
  });
  const set = (k) => (e) => setF((p) => ({ ...p, [k]: e.value }));
  const saving = savingId === (item?.uid || "new");
  const doGen = async () => { const pw = await invoke("generate_password", { length: 20, digits: true, symbols: true, avoidAmbiguous: false }); setF((p) => ({ ...p, password: pw })); };

  if (mode === "newbookmark") {
    return (
      <div className="detail-inner"><div className="edit">
        <div className="detail-title">New bookmark</div>
        <label>Title</label><Input value={f.title} onInput={set("title")} placeholder="My bookmark" />
        <label>URL</label><Input value={f.url} onInput={set("url")} placeholder="https://example.com/" />
        <div className="edit-actions">
          <Button isLoading={saving} onClick={() => onSaveBookmark({ title: f.title, url: f.url, parentGuid: folder }).catch(() => {})}>Save</Button>
          <Button kind="outline" onClick={onCancel}>Cancel</Button>
        </div>
      </div></div>
    );
  }
  if (mode === "newidentity") {
    const fields = [["name","Full name"],["email","Email"],["phone","Phone"],["company","Company"],["street","Street"],["city","City"],["state","State / Province"],["zip","Zip"],["country","Country"]];
    return (
      <div className="detail-inner"><div className="edit">
        <div className="detail-title">New identity</div>
        {fields.map(([k, label]) => <React.Fragment key={k}><label>{label}</label><Input value={f[k]} onInput={set(k)} /></React.Fragment>)}
        <div className="edit-actions">
          <Button isLoading={saving} onClick={() => onSaveIdentity({ name: f.name, email: f.email, phone: f.phone, company: f.company, street: f.street, city: f.city, state: f.state, zip: f.zip, country: f.country }).catch(() => {})}>Save</Button>
          <Button kind="outline" onClick={onCancel}>Cancel</Button>
        </div>
      </div></div>
    );
  }
  // password new/edit
  const isNew = mode === "new";
  return (
    <div className="detail-inner"><div className="edit">
      <div className="detail-title">{isNew ? "New item" : "Edit item"}</div>
      <label>Title</label><Input value={f.title} onInput={set("title")} placeholder="Title" />
      <label>Username</label><Input value={f.username} onInput={set("username")} placeholder="Username" />
      <label>Password</label>
      <div className="row">
        <Input className="grow" value={f.password} onInput={set("password")} placeholder="Password" />
        <Button size="small" kind="outline" onClick={doGen}>Generate</Button>
      </div>
      <label>Website</label>
      <Input value={f.url} onInput={set("url")} placeholder="https://example.com/" disabled={!isNew} />
      <label>Notes</label><Input value={f.notes} onInput={set("notes")} placeholder="Notes" />
      <div className="edit-actions">
        <Button isLoading={saving} onClick={() => onSave({ id: item?.id || "", title: f.title, username: f.username, password: f.password, website: f.url, notes: f.notes }, item?.uid).catch(() => {})}>Save</Button>
        <Button kind="outline" onClick={onCancel}>Cancel</Button>
        <div className="spacer" />
        {!isNew && <Button kind="outline" onClick={() => onDelete(item)}>Delete</Button>}
      </div>
    </div></div>
  );
}

// ---------- Generator modal ----------
function GeneratorModal({ onClose, showToast }) {
  const [len, setLen] = useState(20);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [ambig, setAmbig] = useState(false);
  const [out, setOut] = useState("");
  const run = useCallback(async () => {
    setOut(await invoke("generate_password", { length: len, digits, symbols, avoidAmbiguous: ambig }));
  }, [len, digits, symbols, ambig]);
  useEffect(() => { run(); }, [run]);
  return (
    <div className="modal" onClick={(e) => { if (e.target.classList.contains("modal")) onClose(); }}>
      <div className="modal-card">
        <div className="modal-head"><h2>Password Generator</h2><Button fab kind="plain-faint" onClick={onClose}>✕</Button></div>
        <div className="gen-out">{out || "…"}</div>
        <label className="row-between">Length <span>{len}</span></label>
        <input type="range" min="8" max="64" value={len} onChange={(e) => setLen(+e.target.value)} />
        <Checkbox checked={digits} onChange={(e) => setDigits(e.checked)}>Include numbers</Checkbox>
        <Checkbox checked={symbols} onChange={(e) => setSymbols(e.checked)}>Include symbols</Checkbox>
        <Checkbox checked={ambig} onChange={(e) => setAmbig(e.checked)}>Avoid ambiguous (0 O 1 l I)</Checkbox>
        <div className="modal-actions">
          <Button onClick={run}>Generate</Button>
          <Button kind="outline" onClick={() => out && copyText(out, "Password", showToast)}>Copy</Button>
        </div>
      </div>
    </div>
  );
}
