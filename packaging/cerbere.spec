# -*- mode: python ; coding: utf-8 -*-
"""Spec PyInstaller — Cerbere Security Shield (build onedir).

Usage :
    .venv\\Scripts\\python.exe -m PyInstaller packaging\\cerbere.spec

CERBERE_BUILD_DEBUG=1  ->  build avec console (debug)
"""
import os

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
DEBUG = os.environ.get("CERBERE_BUILD_DEBUG") == "1"

# --- Ressources embarquées (lues via cerbere_paths.project_root()) -----------
_datas_candidates = [
    ("web_port_dashboard/static", "web_port_dashboard/static"),
    ("web_port_dashboard/config.yml", "web_port_dashboard"),
    ("parental_control/curated", "parental_control/curated"),
    ("tracker_filter/data", "tracker_filter/data"),
    ("config", "config"),
    ("scripts/powershell", "scripts/powershell"),
    ("locales", "locales"),  # i18n futur (FR/EN/DE/ES) — ignoré si absent
]
datas = [
    (os.path.join(ROOT, src), dst)
    for src, dst in _datas_candidates
    if os.path.exists(os.path.join(ROOT, src))
]
datas += collect_data_files("pydivert", includes=["windivert_dll/*"])

binaries = collect_dynamic_libs("pydivert")

# pathex : permet à l'analyseur de résoudre les imports « à plat »
# (runtime_collector, intrusion_detector…) utilisés par port_dashboard.
pathex = [
    ROOT,
    os.path.join(ROOT, "web_port_dashboard"),
    os.path.join(ROOT, "scripts", "python"),
]

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "cerbere_paths",
    "web_port_dashboard.port_dashboard",
]

a = Analysis(
    [os.path.join(SPECPATH, "cerbere_launcher.py")],
    pathex=pathex,
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "notebook", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CerbereShield",
    debug=False,
    strip=False,
    upx=False,
    console=DEBUG,
    icon=os.path.join(ROOT, "systray_client", "cerbere.ico"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="CerbereShield",
)
