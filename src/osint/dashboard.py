import sys
from pathlib import Path

HERE = Path(__file__).resolve()
SRC_DIR = HERE.parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

import asyncio
import io
import json
import pickle
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

try:
    from pyvis.network import Network
    PYVIS_OK = True
except Exception:
    PYVIS_OK = False

from osint.services.scanner import run_scan, SCANS_DIR, create_scan_session
from osint.services.transforms import (
    whois_transform_synth,
    related_entities_transform_from_records,
)
from osint.services.credibility import compute_credibility

# ── Design tokens ─────────────────────────────────────────────────────────────
C_BG     = "#0A0E1A"
C_SIDE   = "#0D1321"
C_CARD   = "#111827"
C_BORDER = "#1E2A3A"
C_CYAN   = "#00D4FF"
C_GREEN  = "#00FF88"
C_AMBER  = "#FFB800"
C_RED    = "#FF4444"
C_TEXT   = "#E2E8F0"
C_MUTED  = "#64748B"

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="AEGIS OSINT",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""<style>
html, body, [class*="css"] { background-color: #0A0E1A !important; color: #E2E8F0 !important; }
[data-testid="stAppViewContainer"] { background: #0A0E1A !important; }
[data-testid="stAppViewContainer"] > section > div { background: #0A0E1A !important; }
[data-testid="stHeader"] { background: #0A0E1A !important; border-bottom: 1px solid #1E2A3A !important; }
[data-testid="stToolbar"] { display: none; }
[data-testid="stDecoration"] { display: none; }

section[data-testid="stSidebar"] { background: #0D1321 !important; border-right: 1px solid #1E2A3A !important; }
section[data-testid="stSidebar"] * { color: #E2E8F0 !important; }
section[data-testid="stSidebar"] .stButton > button {
  background: #111827 !important; border: 1px solid #1E2A3A !important;
  color: #E2E8F0 !important; border-radius: 6px !important; font-size: 13px !important;
  text-align: left !important; padding: 8px 12px !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
  background: #1E2A3A !important; border-color: #00D4FF !important; color: #00D4FF !important;
}

.stButton > button {
  background: #111827 !important; border: 1px solid #1E2A3A !important;
  color: #E2E8F0 !important; border-radius: 6px !important; transition: all 0.2s;
}
.stButton > button[kind="primary"] {
  background: #00D4FF !important; border-color: #00D4FF !important;
  color: #0A0E1A !important; font-weight: 700 !important;
}
.stButton > button[kind="primary"]:hover {
  background: #00b8d9 !important; box-shadow: 0 0 14px rgba(0,212,255,0.45) !important;
}

input, textarea {
  background: #111827 !important; color: #E2E8F0 !important;
  border: 1px solid #1E2A3A !important; caret-color: #00D4FF !important; border-radius: 6px !important;
}
input::placeholder, textarea::placeholder { color: #64748B !important; }
input:focus, textarea:focus { border-color: #00D4FF !important; box-shadow: 0 0 0 2px rgba(0,212,255,0.15) !important; }

div[data-baseweb="select"] > div {
  background: #111827 !important; border: 1px solid #1E2A3A !important; border-radius: 6px !important;
}
div[data-baseweb="select"] span, div[data-baseweb="select"] div { color: #E2E8F0 !important; background: transparent !important; }
div[data-baseweb="select"] input { color: #E2E8F0 !important; caret-color: #00D4FF !important; background: transparent !important; }
div[data-baseweb="popover"], ul[role="listbox"] { background: #111827 !important; border: 1px solid #1E2A3A !important; }
li[role="option"] { background: #111827 !important; color: #E2E8F0 !important; }
li[role="option"]:hover { background: #1E2A3A !important; }
div[data-baseweb="tag"] { background: #1E2A3A !important; border: 1px solid #00D4FF !important; color: #00D4FF !important; }

div[role="radiogroup"] label,
div[data-testid="stRadio"] label,
div[data-testid="stCheckbox"] label { color: #E2E8F0 !important; }

div[data-testid="stSlider"] * { color: #E2E8F0 !important; }

div[data-testid="stDataFrame"] { background: #111827 !important; border: 1px solid #1E2A3A !important; border-radius: 8px !important; }
div[data-testid="stDataFrame"] * { color: #E2E8F0 !important; }
div[data-testid="stDataFrame"] div[data-baseweb="popover"] { background: #111827 !important; color: #E2E8F0 !important; }

div[data-testid="stAlert"] { background: #111827 !important; border-radius: 8px !important; }
div[data-testid="stAlert"] * { color: #E2E8F0 !important; }

pre, code { background: #111827 !important; color: #00D4FF !important; border: 1px solid #1E2A3A !important; border-radius: 6px !important; }
div[data-testid="stJson"] * { color: #E2E8F0 !important; }
hr { border-color: #1E2A3A !important; }

label[data-testid="stWidgetLabel"] p { color: #64748B !important; font-size: 12px !important; }

div.stDownloadButton > button {
  background: #111827 !important; color: #00D4FF !important;
  border: 1px solid #00D4FF !important; border-radius: 6px !important;
}

.aegis-card {
  background: #111827; border: 1px solid #1E2A3A;
  border-top: 3px solid #00D4FF; border-radius: 8px; padding: 18px 20px; margin-bottom: 4px;
}
.metric-val { font-size: 30px; font-weight: 800; color: #FFFFFF; font-family: 'Courier New', monospace; line-height: 1.1; }
.metric-lbl { font-size: 11px; color: #64748B; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }
.metric-val.green { color: #00FF88 !important; }
.metric-val.amber { color: #FFB800 !important; }
.metric-val.red   { color: #FF4444 !important; }

.page-header { border-bottom: 1px solid #1E2A3A; padding-bottom: 12px; margin-bottom: 20px; }
.page-breadcrumb { font-size: 11px; color: #64748B; text-transform: uppercase; letter-spacing: 0.1em; }
.page-title { font-size: 22px; font-weight: 700; color: #00D4FF; margin-top: 4px; }

.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: monospace; text-transform: uppercase; letter-spacing: 0.06em; }
.badge-domain  { background: #1e3a5f; color: #60a5fa; }
.badge-email   { background: #3b2b4e; color: #c084fc; }
.badge-ip      { background: #1e3b2e; color: #4ade80; }
.badge-org     { background: #3b2e1e; color: #fb923c; }
.badge-person  { background: #2e1e3b; color: #e879f9; }
.badge-default { background: #1E2A3A; color: #94a3b8; }
.badge-status-completed { background: #1e3b2e; color: #00FF88; }
.badge-status-running   { background: #3b2b1e; color: #FFB800; }
.badge-status-failed    { background: #3b1e1e; color: #FF4444; }

.entity-detail-card {
  background: #111827; border: 1px solid #1E2A3A; border-left: 4px solid #00D4FF;
  border-radius: 8px; padding: 18px;
}
.entity-value { font-size: 16px; font-weight: 700; color: #00D4FF; font-family: 'Courier New', monospace; word-break: break-all; margin: 8px 0; }
.breakdown-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
.breakdown-table th { color: #64748B; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; padding: 5px 8px; border-bottom: 1px solid #1E2A3A; text-align: left; }
.breakdown-table td { padding: 5px 8px; border-bottom: 1px solid #1E2A3A; color: #E2E8F0; font-family: monospace; }
.breakdown-table tr:last-child td { color: #00D4FF; font-weight: 700; border-bottom: none; }

.cred-bar-wrap { width: 100%; background: #1E2A3A; border-radius: 4px; height: 6px; margin-top: 5px; }
.cred-bar-fill { height: 6px; border-radius: 4px; }

.status-dot { width: 8px; height: 8px; border-radius: 50%; background: #00FF88; display: inline-block; margin-right: 6px; box-shadow: 0 0 6px #00FF88; animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
</style>""", unsafe_allow_html=True)


# ── Path helpers ──────────────────────────────────────────────────────────────
def _scan_dir(scan_id: str) -> Path:
    return SCANS_DIR / scan_id


def list_recent_scans(limit: int = 50) -> list:
    if not SCANS_DIR.exists():
        return []
    dirs = [p for p in SCANS_DIR.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [p.name for p in dirs[:limit]]


# ── Cached data loaders ───────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def load_meta(scan_id: str) -> dict:
    p = _scan_dir(scan_id) / "meta.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


@st.cache_data(show_spinner=False)
def load_entities(scan_id: str) -> list:
    p = _scan_dir(scan_id) / "entities.jsonl"
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


@st.cache_data(show_spinner=False)
def load_graph_obj(scan_id: str):
    p = _scan_dir(scan_id) / "graph.gpickle"
    if not p.exists():
        return None
    with p.open("rb") as fh:
        return pickle.load(fh)


@st.cache_data(show_spinner=False)
def load_findings(scan_id: str) -> list:
    p = _scan_dir(scan_id) / "findings.jsonl"
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ── Colour / badge helpers ────────────────────────────────────────────────────
def _cred_color(score) -> str:
    if score is None:
        return C_MUTED
    s = float(score)
    if s > 0.7:
        return C_GREEN
    if s >= 0.4:
        return C_AMBER
    return C_RED


def _cred_class(score) -> str:
    if score is None:
        return ""
    s = float(score)
    if s > 0.7:
        return "green"
    if s >= 0.4:
        return "amber"
    return "red"


def _type_badge(entity_type: str) -> str:
    t = (entity_type or "").lower()
    cls = f"badge-{t}" if t in ("domain", "email", "ip", "org", "person") else "badge-default"
    return f'<span class="badge {cls}">{t or "unknown"}</span>'


def _status_badge(status: str) -> str:
    s = (status or "").lower()
    if s == "completed":
        return f'<span class="badge badge-status-completed">✓ {s}</span>'
    if s in ("running", "active"):
        return f'<span class="badge badge-status-running">● {s}</span>'
    if s == "failed":
        return f'<span class="badge badge-status-failed">✗ {s}</span>'
    return f'<span class="badge badge-default">{s or "—"}</span>'


def _metric_card(label: str, value, color_class: str = "") -> str:
    return (
        f'<div class="aegis-card">'
        f'<div class="metric-val {color_class}">{value}</div>'
        f'<div class="metric-lbl">{label}</div>'
        f'</div>'
    )


def _page_header(breadcrumb: str, title: str) -> None:
    st.markdown(
        f'<div class="page-header">'
        f'<div class="page-breadcrumb">AEGIS OSINT &nbsp;/&nbsp; {breadcrumb}</div>'
        f'<div class="page-title">{title}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _empty_state(msg: str, icon: str = "🛡️") -> None:
    st.markdown(
        f'<div style="background:#111827;border:1px solid #1E2A3A;border-radius:12px;'
        f'padding:60px;text-align:center;margin-top:40px;">'
        f'<div style="font-size:48px;margin-bottom:16px;">{icon}</div>'
        f'<div style="color:#64748B;font-size:15px;">{msg}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _dark_fig(fig):
    fig.update_layout(
        paper_bgcolor=C_BG,
        plot_bgcolor=C_CARD,
        font=dict(color=C_TEXT),
        xaxis=dict(gridcolor=C_BORDER, color=C_TEXT, zerolinecolor=C_BORDER),
        yaxis=dict(gridcolor=C_BORDER, color=C_TEXT),
    )
    return fig


def _node_credibility(node_str: str, node_attrs: dict, ent_lookup: dict):
    """Return credibility score for a graph node, trying multiple sources."""
    # Direct lookup by value
    if node_str in ent_lookup:
        e = ent_lookup[node_str]
        v = e.get("credibility_score") or e.get("credibility")
        if v is not None:
            return float(v)
    # Strip type prefix: "domain:example.com" → "example.com"
    if ":" in node_str:
        val = node_str.split(":", 1)[1]
        if val in ent_lookup:
            e = ent_lookup[val]
            v = e.get("credibility_score") or e.get("credibility")
            if v is not None:
                return float(v)
    # Fall back to node attribute
    v = node_attrs.get("credibility")
    return float(v) if v is not None else None


# ── New-case dialog ───────────────────────────────────────────────────────────
@st.dialog("Create New Case")
def new_case_dialog():
    case_name = st.text_input("Case ID / Name", placeholder="Case-UK-01 | demo_corp")
    st.caption("Creates a case folder. Duplicate names get -2 / -3 suffix auto-appended.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Create", type="primary"):
            out = create_scan_session(case_name or None)
            st.session_state["last_scan_id"] = out["scan_id"]
            st.cache_data.clear()
            st.success(f"Created: {out['scan_id']}")
            st.rerun()
    with c2:
        if st.button("Cancel"):
            st.rerun()


# ── Session-state defaults ────────────────────────────────────────────────────
if "last_scan_id" not in st.session_state:
    recent_all = list_recent_scans()
    if recent_all:
        st.session_state["last_scan_id"] = recent_all[0]

if "nav_page" not in st.session_state:
    st.session_state["nav_page"] = "Dashboard"


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        '<div style="padding:8px 0 16px;">'
        '<div style="font-size:22px;font-weight:800;color:#00D4FF;letter-spacing:0.05em;">🛡️ AEGIS OSINT</div>'
        '<div style="font-size:11px;color:#64748B;margin-top:2px;letter-spacing:0.12em;">INTELLIGENCE PLATFORM</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div style="font-size:10px;color:#64748B;text-transform:uppercase;'
        'letter-spacing:0.12em;margin-bottom:6px;">Navigation</div>',
        unsafe_allow_html=True,
    )
    _pages = [
        ("📊", "Dashboard"),
        ("🗂️", "Case Workspace"),
        ("🔗", "Entity Graph"),
        ("📈", "Credibility Analysis"),
        ("📡", "Findings Feed"),
    ]
    cur_page = st.session_state["nav_page"]
    for icon, pname in _pages:
        indicator = " ◉" if cur_page == pname else ""
        if st.button(f"{icon}  {pname}{indicator}", key=f"nav_{pname}", use_container_width=True):
            st.session_state["nav_page"] = pname
            st.rerun()

    st.markdown('<hr style="border-color:#1E2A3A;margin:12px 0;">', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-size:10px;color:#64748B;text-transform:uppercase;'
        'letter-spacing:0.12em;margin-bottom:6px;">Case Manager</div>',
        unsafe_allow_html=True,
    )

    if st.button("➕ New Case", use_container_width=True):
        new_case_dialog()

    _recent = list_recent_scans()
    _default = st.session_state.get("last_scan_id")
    _idx = (_recent.index(_default) + 1) if (_default in _recent) else 0
    _chosen = st.selectbox(
        "Load Case", options=["(none)"] + _recent, index=_idx, label_visibility="collapsed",
    )
    if _chosen != "(none)" and _chosen != _default:
        st.session_state["last_scan_id"] = _chosen
        st.cache_data.clear()
        st.rerun()

    _scan_id_sb = st.session_state.get("last_scan_id")
    if _scan_id_sb:
        _m = load_meta(_scan_id_sb)
        st.markdown(
            f'<div style="background:#111827;border:1px solid #1E2A3A;border-left:3px solid #00D4FF;'
            f'border-radius:6px;padding:10px 12px;margin-top:8px;">'
            f'<div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.1em;">Active Case</div>'
            f'<div style="font-family:monospace;color:#00D4FF;font-size:13px;margin-top:4px;">{_scan_id_sb}</div>'
            f'<div style="color:#64748B;font-size:12px;margin-top:4px;">Target: '
            f'<span style="color:#E2E8F0">{_m.get("target","—")}</span></div>'
            f'<div style="color:#64748B;font-size:12px;">Status: '
            f'<span style="color:#E2E8F0">{_m.get("status","—")}</span></div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown('<div style="color:#64748B;font-size:12px;margin-top:8px;">No case loaded.</div>', unsafe_allow_html=True)

    st.markdown('<hr style="border-color:#1E2A3A;margin:12px 0;">', unsafe_allow_html=True)
    _now_str = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    st.markdown(
        f'<div style="font-size:11px;color:#64748B;">'
        f'<span class="status-dot"></span><span style="color:#00FF88;">ONLINE</span>'
        f'&nbsp;·&nbsp; {_now_str}</div>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE 1 — DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
def page_dashboard():
    _page_header("Overview", "Dashboard")

    scan_id = st.session_state.get("last_scan_id")
    all_scans = list_recent_scans()

    if scan_id:
        ents = load_entities(scan_id)
        G = load_graph_obj(scan_id)
        n_ents = len(ents)
        n_nodes = G.number_of_nodes() if G else 0
        n_edges = G.number_of_edges() if G else 0
        scores = [
            float(e.get("credibility_score") or e.get("credibility") or 0)
            for e in ents
            if (e.get("credibility_score") is not None or e.get("credibility") is not None)
        ]
        avg_cred = round(sum(scores) / len(scores), 3) if scores else None
    else:
        ents, G, n_ents, n_nodes, n_edges, avg_cred = [], None, 0, 0, 0, None

    cred_cls = _cred_class(avg_cred)
    cred_disp = f"{avg_cred:.3f}" if avg_cred is not None else "N/A"

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, lbl, val, cls in zip(
        [c1, c2, c3, c4, c5],
        ["Total Cases", "Total Entities", "Graph Nodes", "Graph Edges", "Avg Credibility"],
        [len(all_scans), n_ents, n_nodes, n_edges, cred_disp],
        ["", "", "", "", cred_cls],
    ):
        with col:
            st.markdown(_metric_card(lbl, val, cls), unsafe_allow_html=True)

    st.markdown('<div style="margin-top:24px;"></div>', unsafe_allow_html=True)
    left, right = st.columns([1.2, 1], gap="large")

    with left:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;margin-bottom:10px;'
            'text-transform:uppercase;letter-spacing:0.08em;">Recent Cases</div>',
            unsafe_allow_html=True,
        )
        if not all_scans:
            _empty_state("No cases yet. Create a case from the sidebar.", "🗂️")
        else:
            rows = []
            for sid in all_scans[:20]:
                m = load_meta(sid)
                ep = _scan_dir(sid) / "entities.jsonl"
                n_e = sum(1 for ln in ep.open() if ln.strip()) if ep.exists() else 0
                rows.append({
                    "Case ID": sid,
                    "Target": m.get("target", "—"),
                    "Status": m.get("status", "—"),
                    "Entities": n_e,
                    "Created": m.get("created_at", m.get("fetched_at", "—")),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, height=380, hide_index=True)

    with right:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;margin-bottom:10px;'
            'text-transform:uppercase;letter-spacing:0.08em;">Entity Type Distribution</div>',
            unsafe_allow_html=True,
        )
        if not ents:
            _empty_state("No entities in current case.", "📊")
        else:
            tc: dict = {}
            for e in ents:
                t = e.get("type", "unknown")
                tc[t] = tc.get(t, 0) + 1
            tdf = pd.DataFrame(sorted(tc.items(), key=lambda x: x[1]), columns=["Type", "Count"])
            fig = px.bar(tdf, x="Count", y="Type", orientation="h", template="plotly_dark")
            fig.update_traces(marker_color=C_CYAN)
            _dark_fig(fig)
            fig.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0), showlegend=False)
            st.plotly_chart(fig, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE 2 — CASE WORKSPACE
# ═══════════════════════════════════════════════════════════════════════════════
def page_case_workspace():
    _page_header("Case Workspace", "Case Workspace")

    scan_id = st.session_state.get("last_scan_id")
    if not scan_id:
        _empty_state("No case loaded. Create or select a case from the sidebar.", "🗂️")
        return

    meta = load_meta(scan_id)
    ents = load_entities(scan_id)
    G = load_graph_obj(scan_id)

    status = meta.get("status", "—")
    target = meta.get("target", "—")
    created = meta.get("created_at", meta.get("fetched_at", "—"))

    st.markdown(
        f'<div style="background:#111827;border:1px solid #1E2A3A;border-left:4px solid #00D4FF;'
        f'border-radius:8px;padding:14px 20px;margin-bottom:20px;">'
        f'<div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">'
        f'<div><div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.1em;">Case ID</div>'
        f'<div style="font-family:monospace;color:#00D4FF;font-size:16px;font-weight:700;">{scan_id}</div></div>'
        f'<div style="width:1px;height:36px;background:#1E2A3A;"></div>'
        f'<div><div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.1em;">Target</div>'
        f'<div style="font-family:monospace;color:#E2E8F0;font-size:14px;">{target}</div></div>'
        f'<div style="width:1px;height:36px;background:#1E2A3A;"></div>'
        f'<div><div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.1em;">Status</div>'
        f'<div style="font-size:14px;margin-top:2px;">{_status_badge(status)}</div></div>'
        f'<div style="width:1px;height:36px;background:#1E2A3A;"></div>'
        f'<div><div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.1em;">Created</div>'
        f'<div style="font-family:monospace;color:#E2E8F0;font-size:12px;">{created}</div></div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    scores = [
        float(e.get("credibility_score") or e.get("credibility") or 0)
        for e in ents
        if (e.get("credibility_score") is not None or e.get("credibility") is not None)
    ]
    avg_cred = round(sum(scores) / len(scores), 3) if scores else 0

    m1, m2, m3, m4 = st.columns(4)
    for col, lbl, val in zip(
        [m1, m2, m3, m4],
        ["Entities", "Graph Nodes", "Graph Edges", "Avg Credibility"],
        [len(ents), G.number_of_nodes() if G else 0, G.number_of_edges() if G else 0, avg_cred],
    ):
        with col:
            st.markdown(_metric_card(lbl, val), unsafe_allow_html=True)

    st.markdown('<div style="margin-top:24px;"></div>', unsafe_allow_html=True)
    collect_col, transform_col = st.columns([1, 1.1], gap="large")

    with collect_col:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:12px;">🔍 Collection</div>',
            unsafe_allow_html=True,
        )
        mode = st.radio("Collection mode", ["Synthetic (Demo)", "Live (Authorized)"], horizontal=True)
        if mode == "Live (Authorized)":
            st.warning("Live mode: only use targets you own or have explicit written permission to test.", icon="⚠️")

        scan_name = st.text_input("Case ID override", value=scan_id)

        if mode == "Live (Authorized)":
            target_input = st.text_input("Target (Domain / URL / IP)", placeholder="yourdomain.com | 1.2.3.4")
            st.caption("WHOIS/DNS/HTTP work with a domain/URL. Shodan works best with a public IP.")
        else:
            target_input = st.text_input("Target (Seed Entity)", placeholder="examplecorp.com | 8.8.8.8 | admin@example.com")
            st.caption("Synthetic mode provides reproducible demos without live network calls.")

        UI_MODULES_LIVE = {
            "WHOIS (Live)": "sfp_whois_live",
            "DNS (Live)": "sfp_dns_live",
            "HTTP Headers (Live)": "sfp_http_live",
            "Shodan Exposure (Live)": "sfp_shodan",
        }
        UI_MODULES_SYNTH = {"Shodan Exposure (Synthetic)": "sfp_shodan"}
        UI_MODULES = UI_MODULES_LIVE if mode == "Live (Authorized)" else UI_MODULES_SYNTH

        selected_labels = st.multiselect("Modules", list(UI_MODULES.keys()), default=list(UI_MODULES.keys()))
        selected_keys = [UI_MODULES[x] for x in selected_labels]

        if st.button("🚀 Run Collection", type="primary", use_container_width=True):
            if not target_input:
                st.error("Enter a target.")
            elif not selected_keys:
                st.error("Select at least one module.")
            else:
                with st.spinner("Running collection modules…"):
                    result = asyncio.run(run_scan(target_input, selected_keys, scan_name=scan_name or None))
                if "error" in result:
                    st.error(f"Collection failed: {result.get('error')}")
                    st.code(json.dumps(result, indent=2), language="json")
                else:
                    st.session_state["last_scan_id"] = result["scan_id"]
                    st.cache_data.clear()
                    st.success(f"Complete: {result['scan_id']}")
                    st.rerun()

    with transform_col:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:12px;">⚡ Transforms</div>',
            unsafe_allow_html=True,
        )
        if not G:
            _empty_state("Run collection to build a graph, then apply transforms here.", "⚡")
        else:
            node_list = sorted([str(n) for n in G.nodes()])
            selected_node = st.selectbox("Select node to transform", node_list)
            records_path = HERE.parents[2] / "data" / "outputs" / "records.jsonl"

            tc1, tc2 = st.columns(2)
            with tc1:
                if st.button("🔍 WHOIS Transform", use_container_width=True):
                    with st.spinner("Running WHOIS transform…"):
                        out = whois_transform_synth(_scan_dir(scan_id), selected_node)
                    st.success(f"Done: {out}")
                    st.cache_data.clear()
                    st.rerun()
            with tc2:
                if st.button("🔗 Related Entities", use_container_width=True):
                    with st.spinner("Extracting related entities…"):
                        out = related_entities_transform_from_records(_scan_dir(scan_id), selected_node, records_path)
                    if "error" in out:
                        st.error(out["error"])
                        st.caption(f"Expected records file at: {records_path}")
                    else:
                        st.success(f"Done: {out}")
                    st.cache_data.clear()
                    st.rerun()

        st.markdown('<div style="margin-top:20px;"></div>', unsafe_allow_html=True)
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:8px;">📥 Export</div>',
            unsafe_allow_html=True,
        )
        if ents:
            csv_buf = io.StringIO()
            pd.DataFrame(ents).to_csv(csv_buf, index=False)
            st.download_button(
                "Download Entities CSV", csv_buf.getvalue().encode(),
                "entities.csv", "text/csv", use_container_width=True,
            )
        else:
            st.markdown('<div style="color:#64748B;font-size:13px;">No entities to export yet.</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE 3 — ENTITY GRAPH
# ═══════════════════════════════════════════════════════════════════════════════
def page_entity_graph():
    _page_header("Entity Graph", "Entity Graph")

    scan_id = st.session_state.get("last_scan_id")
    if not scan_id:
        _empty_state("No case loaded. Select a case from the sidebar.", "🔗")
        return

    G = load_graph_obj(scan_id)
    ents = load_entities(scan_id)

    if not G:
        _empty_state("No graph available. Run collection first.", "🔗")
        return
    if not PYVIS_OK:
        st.error("pyvis not installed: pip install pyvis")
        return

    ent_lookup = {e.get("value", ""): e for e in ents if e.get("value")}

    # Controls
    ctrl1, ctrl2, ctrl3 = st.columns([1.2, 2.5, 0.8])
    with ctrl1:
        threshold = st.slider("Credibility Threshold", 0.0, 1.0, 0.4, 0.05,
                              help="Entities below this score are excluded from the graph")
    with ctrl2:
        all_types = sorted({
            attrs.get("type", "")
            for _, attrs in G.nodes(data=True)
            if attrs.get("type")
        })
        type_filter = st.multiselect("Entity Types", all_types, default=all_types)
    with ctrl3:
        show_sup = st.checkbox("Show suppressed count", value=True)

    # Count suppressed
    suppressed = sum(
        1 for node, attrs in G.nodes(data=True)
        if attrs.get("kind") == "entity"
        and (_node_credibility(str(node), attrs, ent_lookup) or 0) < threshold
    )

    if show_sup:
        admitted = G.number_of_nodes() - suppressed
        st.markdown(
            f'<div style="background:#111827;border:1px solid #1E2A3A;border-radius:6px;'
            f'padding:8px 16px;margin-bottom:12px;display:inline-flex;gap:24px;align-items:center;">'
            f'<span><span style="color:#64748B;font-size:12px;">Suppressed: </span>'
            f'<span style="color:#FF4444;font-family:monospace;font-weight:700;font-size:16px;">{suppressed}</span></span>'
            f'<span><span style="color:#64748B;font-size:12px;">Admitted: </span>'
            f'<span style="color:#00FF88;font-family:monospace;font-weight:700;font-size:16px;">{admitted}</span></span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    graph_col, detail_col = st.columns([2, 1], gap="large")

    with graph_col:
        net = Network(height="580px", width="100%", directed=False, bgcolor=C_BG, font_color=C_TEXT)
        net.barnes_hut()

        admitted_nodes: set = set()
        for node, attrs in G.nodes(data=True):
            nstr = str(node)
            kind = attrs.get("kind", "entity")
            ntype = attrs.get("type", "")
            cred = _node_credibility(nstr, attrs, ent_lookup)

            if kind == "entity":
                cred_val = float(cred) if cred is not None else 0.0
                if cred_val < threshold:
                    continue
                if type_filter and ntype and ntype not in type_filter:
                    continue

            admitted_nodes.add(nstr)
            color = _cred_color(cred) if kind == "entity" else C_MUTED
            size = (15 + float(cred) * 20) if (kind == "entity" and cred is not None) else 12

            # Build tooltip from entity data
            ent_data = ent_lookup.get(nstr) or (
                ent_lookup.get(nstr.split(":", 1)[1]) if ":" in nstr else {}
            ) or {}
            bd = (ent_data.get("meta") or {}).get("credibility_breakdown") or {}

            tooltip = "\n".join([
                f"Type: {attrs.get('type', kind)}",
                f"Value: {nstr.split(':', 1)[-1] if ':' in nstr else nstr}",
                f"Credibility: {round(cred, 4) if cred is not None else 'N/A'}",
                f"Provenance: {attrs.get('provenance_source', ent_data.get('provenance', 'N/A'))}",
                f"Age (days): {bd.get('age_days', 'N/A')}",
                f"Decay Factor: {bd.get('decay_factor', 'N/A')}",
                f"Formula: {bd.get('formula', 'N/A')}",
                f"First Seen: {attrs.get('first_seen', ent_data.get('first_seen', 'N/A'))}",
                f"Last Seen: {attrs.get('last_seen', ent_data.get('last_seen', 'N/A'))}",
            ])

            label = nstr[:28] + "…" if len(nstr) > 28 else nstr
            net.add_node(nstr, label=label, color=color, size=size, title=tooltip,
                         font={"color": C_TEXT, "size": 11})

        for u, v, eattrs in G.edges(data=True):
            if str(u) in admitted_nodes and str(v) in admitted_nodes:
                net.add_edge(str(u), str(v),
                             title=str(eattrs.get("rel", eattrs.get("module", ""))),
                             color="#2A3A4A", width=1.5)

        net.set_options(json.dumps({
            "nodes": {"borderWidth": 1, "borderWidthSelected": 2},
            "edges": {"color": {"color": "#2A3A4A", "highlight": C_CYAN}, "smooth": {"type": "dynamic"}},
            "physics": {
                "enabled": True,
                "barnesHut": {
                    "gravitationalConstant": -8000,
                    "centralGravity": 0.3,
                    "springLength": 200,
                    "springConstant": 0.04,
                    "damping": 0.09,
                },
            },
            "interaction": {"hover": True, "tooltipDelay": 150, "navigationButtons": True},
        }))

        html_path = _scan_dir(scan_id) / "graph_view.html"
        net.write_html(str(html_path))
        raw_html = html_path.read_text(encoding="utf-8")
        # Inject dark background override
        dark_css = (
            f"<style>body,html{{background:{C_BG}!important;margin:0;padding:0;}}"
            f"#mynetwork{{background:{C_BG}!important;}}</style>"
        )
        raw_html = raw_html.replace("</head>", dark_css + "</head>")
        components.html(raw_html, height=600, scrolling=False)

    with detail_col:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:10px;">Entity Detail</div>',
            unsafe_allow_html=True,
        )
        if not ents:
            st.markdown(
                '<div style="color:#64748B;font-size:13px;padding:20px;background:#111827;'
                'border-radius:8px;border:1px solid #1E2A3A;text-align:center;">No entities loaded.</div>',
                unsafe_allow_html=True,
            )
        else:
            opts = [f"{e.get('type','?')}:{e.get('value','')}" for e in ents]
            chosen_opt = st.selectbox("Select entity", opts, key="entity_detail_sel")
            idx = opts.index(chosen_opt) if chosen_opt in opts else 0
            ent = ents[idx]

            etype = ent.get("type", "unknown")
            evalue = ent.get("value", "")
            prov = ent.get("provenance", "unknown")
            cred_score = float(ent.get("credibility_score") or ent.get("credibility") or 0)
            meta_obj = ent.get("meta") or {}
            bd = meta_obj.get("credibility_breakdown") or {}

            corr = float(bd.get("corroboration") or 0)
            rep = float(bd.get("source_reputation") or 0)
            decay = float(bd.get("decay_factor") or 1.0)
            age_days = bd.get("age_days")
            half_life = float(bd.get("half_life_days") or 30)
            formula = bd.get("formula", "N/A")
            sources_seen = bd.get("sources_seen") or []
            first_seen = ent.get("first_seen", "N/A")
            last_seen = ent.get("last_seen", "N/A")
            bar_color = _cred_color(cred_score)
            bar_pct = int(cred_score * 100)

            # Determine mode from formula to build correct breakdown rows
            if bd.get("mode") == "temporal" or "0.5" in str(formula):
                bd_rows = [
                    ("Corroboration", "0.5", f"{corr:.3f}", f"{0.5 * corr:.4f}"),
                    ("Source Reputation", "0.3", f"{rep:.3f}", f"{0.3 * rep:.4f}"),
                    ("Temporal Decay", "0.2", f"{decay:.3f}", f"{0.2 * decay:.4f}"),
                    ("TOTAL", "1.0", "—", f"{cred_score:.4f}"),
                ]
            else:
                bd_rows = [
                    ("Corroboration", "0.6", f"{corr:.3f}", f"{0.6 * corr:.4f}"),
                    ("Source Reputation", "0.4", f"{rep:.3f}", f"{0.4 * rep:.4f}"),
                    ("TOTAL", "1.0", "—", f"{cred_score:.4f}"),
                ]

            bd_html = "".join(
                f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>"
                for r in bd_rows
            )

            if age_days is not None:
                age_pct = min(100, int((float(age_days) / (half_life * 2)) * 100))
                age_color = C_GREEN if float(age_days) < 7 else (C_AMBER if float(age_days) < 30 else C_RED)
                age_html = (
                    f'<div style="margin-top:10px;">'
                    f'<div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.08em;">Age vs Half-life</div>'
                    f'<div style="display:flex;align-items:center;gap:8px;margin-top:4px;">'
                    f'<div class="cred-bar-wrap" style="flex:1;">'
                    f'<div class="cred-bar-fill" style="width:{age_pct}%;background:{age_color};"></div></div>'
                    f'<span style="font-family:monospace;font-size:12px;color:{age_color};">{float(age_days):.1f}d</span>'
                    f'</div>'
                    f'<div style="font-size:10px;color:#64748B;">Half-life: {half_life:.0f}d</div>'
                    f'</div>'
                )
            else:
                age_html = '<div style="color:#64748B;font-size:12px;margin-top:8px;">Age data not available</div>'

            src_badges = " ".join(
                f'<span class="badge badge-default" style="margin-right:3px;">{s}</span>'
                for s in sources_seen
            )

            st.markdown(
                f'<div class="entity-detail-card">'
                f'{_type_badge(etype)}'
                f'<div class="entity-value">{evalue}</div>'
                f'<div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.08em;">Credibility Score</div>'
                f'<div style="font-family:monospace;font-size:22px;color:{bar_color};font-weight:700;margin-top:2px;">{cred_score:.4f}</div>'
                f'<div class="cred-bar-wrap"><div class="cred-bar-fill" style="width:{bar_pct}%;background:{bar_color};"></div></div>'
                f'<table class="breakdown-table"><thead><tr>'
                f'<th>Component</th><th>Wt</th><th>Score</th><th>Contrib</th>'
                f'</tr></thead><tbody>{bd_html}</tbody></table>'
                f'{age_html}'
                f'<div style="margin-top:10px;">'
                f'<div style="font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:0.08em;">Provenance</div>'
                f'<div style="font-family:monospace;color:#E2E8F0;font-size:12px;margin-top:3px;">{prov}</div>'
                f'<div style="margin-top:4px;">{src_badges}</div></div>'
                f'<div style="margin-top:8px;font-size:11px;color:#64748B;">'
                f'First seen: {first_seen}<br>Last seen: {last_seen}</div>'
                f'<div style="margin-top:6px;font-size:10px;color:#64748B;">Formula: '
                f'<code style="color:#00D4FF;background:transparent;border:none;padding:0;">{formula}</code></div>'
                f'</div>',
                unsafe_allow_html=True,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE 4 — CREDIBILITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def page_credibility_analysis():
    _page_header("Credibility Analysis", "Credibility Analysis")

    scan_id = st.session_state.get("last_scan_id")
    if not scan_id:
        _empty_state("No case loaded. Select a case from the sidebar.", "📈")
        return

    ents_raw = load_entities(scan_id)
    if not ents_raw:
        _empty_state("No entities in this case. Run collection first.", "📈")
        return

    mode_col, _ = st.columns([1, 3])
    with mode_col:
        score_mode = st.radio("Scoring mode", ["Temporal", "Static"], horizontal=True)
    mode_key = "temporal" if score_mode == "Temporal" else "static"

    scored = compute_credibility([dict(e) for e in ents_raw], mode=mode_key)

    rows = []
    for e in scored:
        bd = (e.get("meta") or {}).get("credibility_breakdown") or {}
        rows.append({
            "value": str(e.get("value", "")),
            "type": str(e.get("type", "unknown")),
            "provenance": str(e.get("provenance", "unknown")),
            "credibility_score": round(float(e.get("credibility_score") or 0), 4),
            "age_days": bd.get("age_days"),
            "decay_factor": bd.get("decay_factor"),
            "corroboration": bd.get("corroboration"),
            "source_reputation": bd.get("source_reputation"),
            "first_seen": e.get("first_seen"),
            "last_seen": e.get("last_seen"),
        })
    df = pd.DataFrame(rows)

    # ── Score distribution histogram ──────────────────────────────────────────
    st.markdown(
        '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
        'letter-spacing:0.08em;margin-bottom:10px;">Score Distribution</div>',
        unsafe_allow_html=True,
    )
    fig_hist = go.Figure()
    bins = [i * 0.05 for i in range(21)]
    for i in range(len(bins) - 1):
        lo, hi = bins[i], bins[i + 1]
        count = len(df[(df["credibility_score"] >= lo) & (df["credibility_score"] < hi)])
        if count:
            color = C_GREEN if hi > 0.7 else (C_AMBER if hi > 0.4 else C_RED)
            fig_hist.add_trace(go.Bar(x=[(lo + hi) / 2], y=[count], width=0.045,
                                      marker_color=color, showlegend=False))
    for thresh, color, label in [(0.4, C_AMBER, "τ=0.40"), (0.7, C_GREEN, "τ=0.70")]:
        fig_hist.add_vline(x=thresh, line_dash="dash", line_color=color,
                           annotation_text=label, annotation_font=dict(color=color, size=11))
    fig_hist.update_layout(
        template="plotly_dark", paper_bgcolor=C_BG, plot_bgcolor=C_CARD,
        font=dict(color=C_TEXT), height=250, margin=dict(l=0, r=0, t=20, b=0),
        xaxis=dict(title="Credibility Score", range=[0, 1], gridcolor=C_BORDER, color=C_TEXT),
        yaxis=dict(title="Count", gridcolor=C_BORDER, color=C_TEXT), bargap=0.02,
    )
    st.plotly_chart(fig_hist, use_container_width=True)

    # ── Box by type + bar by provenance ───────────────────────────────────────
    bleft, bright = st.columns(2, gap="large")

    with bleft:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:8px;">Score by Entity Type</div>',
            unsafe_allow_html=True,
        )
        fig_box = px.box(df, x="credibility_score", y="type", orientation="h",
                         color="type", template="plotly_dark")
        fig_box.update_layout(
            paper_bgcolor=C_BG, plot_bgcolor=C_CARD, font=dict(color=C_TEXT),
            height=280, margin=dict(l=0, r=0, t=10, b=0), showlegend=False,
            xaxis=dict(range=[0, 1], gridcolor=C_BORDER, color=C_TEXT),
            yaxis=dict(gridcolor=C_BORDER, color=C_TEXT),
        )
        st.plotly_chart(fig_box, use_container_width=True)

    with bright:
        st.markdown(
            '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
            'letter-spacing:0.08em;margin-bottom:8px;">Mean Score by Provenance</div>',
            unsafe_allow_html=True,
        )
        prov_means = (
            df.groupby("provenance")["credibility_score"].mean()
            .reset_index()
            .rename(columns={"credibility_score": "mean_score"})
            .sort_values("mean_score")
        )
        fig_prov = px.bar(
            prov_means, x="mean_score", y="provenance", orientation="h",
            color="mean_score",
            color_continuous_scale=[[0, C_RED], [0.4, C_AMBER], [0.7, C_GREEN], [1, C_GREEN]],
            range_color=[0, 1], template="plotly_dark",
        )
        fig_prov.update_layout(
            paper_bgcolor=C_BG, plot_bgcolor=C_CARD, font=dict(color=C_TEXT),
            height=280, margin=dict(l=0, r=0, t=10, b=0),
            showlegend=False, coloraxis_showscale=False,
            xaxis=dict(range=[0, 1], gridcolor=C_BORDER, color=C_TEXT),
            yaxis=dict(gridcolor=C_BORDER, color=C_TEXT),
        )
        st.plotly_chart(fig_prov, use_container_width=True)

    # ── Temporal decay table ──────────────────────────────────────────────────
    st.markdown(
        '<div style="font-size:13px;font-weight:700;color:#E2E8F0;text-transform:uppercase;'
        'letter-spacing:0.08em;margin:16px 0 8px;">Temporal Decay Details</div>',
        unsafe_allow_html=True,
    )

    def _age_status(age):
        if age is None:
            return "UNKNOWN"
        a = float(age)
        if a < 7:   return "FRESH"
        if a < 30:  return "AGING"
        if a < 60:  return "STALE"
        return "EXPIRED"

    df_t = df.copy()
    df_t["status"] = df_t["age_days"].apply(_age_status)
    df_t = df_t.sort_values("age_days", ascending=False, na_position="last")
    show_cols = [c for c in ["value", "type", "age_days", "decay_factor", "corroboration",
                              "credibility_score", "status"] if c in df_t.columns]
    st.dataframe(df_t[show_cols], use_container_width=True, height=380, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE 5 — FINDINGS FEED
# ═══════════════════════════════════════════════════════════════════════════════
def page_findings_feed():
    _page_header("Findings Feed", "Findings Feed")

    scan_id = st.session_state.get("last_scan_id")
    if not scan_id:
        _empty_state("No case loaded. Select a case from the sidebar.", "📡")
        return

    findings_list = load_findings(scan_id)
    if not findings_list:
        _empty_state("No findings yet. Run collection or transforms.", "📡")
        return

    df = pd.DataFrame(findings_list)
    _HIGH_TYPES = {"ip", "domain", "email"}

    def _severity(row: dict) -> str:
        try:
            conf = float(row.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0.0
        etype = str(row.get("entity_type") or "").lower()
        if conf > 0.7 and etype in _HIGH_TYPES:
            return "HIGH"
        if conf < 0.4 and conf > 0:
            return "LOW"
        return "MEDIUM"

    df["severity"] = df.apply(lambda r: _severity(r.to_dict()), axis=1)

    # Filter controls
    fc1, fc2, fc3 = st.columns([1, 1.5, 1.5])
    with fc1:
        sev_filter = st.multiselect("Severity", ["HIGH", "MEDIUM", "LOW"],
                                    default=["HIGH", "MEDIUM", "LOW"])
    with fc2:
        all_etypes = sorted(df["entity_type"].dropna().unique().tolist()) if "entity_type" in df.columns else []
        type_filter_f = st.multiselect("Entity Type", ["(all)"] + all_etypes, default=["(all)"])
    with fc3:
        search_q = st.text_input("🔍 Search value", placeholder="domain, IP, email…")

    view = df.copy()
    if sev_filter:
        view = view[view["severity"].isin(sev_filter)]
    if type_filter_f and "(all)" not in type_filter_f:
        view = view[view["entity_type"].isin(type_filter_f)]
    if search_q and "value" in view.columns:
        view = view[view["value"].astype(str).str.contains(search_q, case=False, na=False)]

    view = view.sort_values("ts", ascending=False).head(200) if "ts" in view.columns else view.head(200)
    sev_icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
    view = view.copy()
    view["⚠"] = view["severity"].map(sev_icons)

    show_cols = [c for c in ["ts", "⚠", "entity_type", "value", "module",
                              "event_type", "confidence", "severity"] if c in view.columns]
    col_cfg: dict = {}
    if "confidence" in view.columns:
        col_cfg["confidence"] = st.column_config.ProgressColumn(
            "Credibility", min_value=0.0, max_value=1.0, format="%.3f",
        )

    st.dataframe(view[show_cols], use_container_width=True, height=460,
                 hide_index=True, column_config=col_cfg)

    exp_col, stat_col = st.columns([1, 3])
    with exp_col:
        buf = io.StringIO()
        view.to_csv(buf, index=False)
        st.download_button("📥 Export CSV", buf.getvalue().encode(),
                           "findings.csv", "text/csv", use_container_width=True)
    with stat_col:
        n_high = int((view["severity"] == "HIGH").sum())
        n_med  = int((view["severity"] == "MEDIUM").sum())
        n_low  = int((view["severity"] == "LOW").sum())
        st.markdown(
            f'<div style="display:flex;gap:20px;padding:10px 0;align-items:center;">'
            f'<span style="color:#FF4444;font-size:13px;">🔴 HIGH: <b>{n_high}</b></span>'
            f'<span style="color:#FFB800;font-size:13px;">🟡 MEDIUM: <b>{n_med}</b></span>'
            f'<span style="color:#00FF88;font-size:13px;">🟢 LOW: <b>{n_low}</b></span>'
            f'<span style="color:#64748B;font-size:12px;">Showing {len(view)} events</span>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTER
# ═══════════════════════════════════════════════════════════════════════════════
_page = st.session_state.get("nav_page", "Dashboard")
if   _page == "Dashboard":           page_dashboard()
elif _page == "Case Workspace":      page_case_workspace()
elif _page == "Entity Graph":        page_entity_graph()
elif _page == "Credibility Analysis": page_credibility_analysis()
elif _page == "Findings Feed":       page_findings_feed()
