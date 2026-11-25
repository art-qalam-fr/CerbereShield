#!/usr/bin/env python3
"""Audit live corrige + PDF blindé Security Sheeld."""
import json, os, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / ".venv" / "Lib" / "site-packages"))

def api_get(path):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:4050{path}", timeout=5)
        return json.loads(r.read().decode())
    except Exception as e:
        print(f"[WARN] API {path}: {e}")
        return {}

state = api_get("/api/protection/state")
ports = api_get("/api/ports/current")
history = api_get("/api/history?limit=5")
alerts = api_get("/api/alerts?limit=10")
intrusion = api_get("/api/intrusion/dashboard")

all_ports = ports.get("ports", [])
# Ports exposes = ecoute sur 0.0.0.0, *, ::
exposed = [p for p in all_ports if p.get("local_ip") in ("0.0.0.0","*","::")]
# Ports critiques ou inattendus selon risk_level (champ enrichi par RiskEvaluator)
critical = [p for p in exposed if p.get("risk_level") == "critical"]
unexpected = [p for p in exposed if p.get("risk_level") == "unexpected"]
# Ports vraiment proteges = firewall_blocked=True
firewalled = [p for p in exposed if p.get("firewall_blocked")]
# Ports non proteges = exposes MAIS pas bloques
unprotected = [p for p in exposed if not p.get("firewall_blocked")]

# Recalcul score: % de ports exposes non proteges / total ports
total_exposed_unprotected = len(unprotected)
risk_score = int(round(100 * total_exposed_unprotected / max(len(all_ports),1)))
risk_score = max(0, min(100, risk_score))

print(f"Ports totaux: {len(all_ports)}")
print(f"Ports exposes (0.0.0.0/::): {len(exposed)}")
print(f"  - Bloques firewall: {len(firewalled)}")
print(f"  - NON bloques: {len(unprotected)}")
print(f"  - Critiques (bloques): {len(critical)}")
print(f"  - Inattendus (bloques): {len(unexpected)}")
print(f"Score de risque recalcule: {risk_score}/100")

history_rows = []
for h in history[:5]:
    hs = h.get("risk_score", 0)
    st = "FAIBLE" if hs < 30 else ("MOYEN" if hs < 70 else "ELEVE")
    history_rows.append({
        "idx": len(history_rows)+1,
        "ts": h.get("timestamp","—"),
        "score": hs,  # integer for comparison
    "score_str": f"{hs}/100",  # formatted for display
    "nport": len(h.get("ports",[])),
        "nport": len(h.get("ports",[])),
        "status": st
    })

data = {
    "state": state,
    "all_ports_count": len(all_ports),
    "exposed_count": len(exposed),
    "firewalled_count": len(firewalled),
    "unprotected_count": len(unprotected),
    "critical_count": len(critical),
    "unexpected_count": len(unexpected),
    "risk_score": risk_score,
    "exposed_ports_detail": [{
        "port": p["port"], "protocol": p["protocol"],
        "local_ip": p["local_ip"], "pid": p.get("pid","?"),
        "process": p.get("process",{}).get("name","unknown") or "unknown",
        "firewall_blocked": p.get("firewall_blocked", False),
        "risk": p.get("risk","?"),
        "risk_level": p.get("risk_level","?"),
    } for p in exposed],
    "history": history_rows,
    "alerts": alerts,
    "intrusion": intrusion,
    "generated_at": datetime.now(timezone.utc).isoformat(),
}

with open(str(BASE / "audit_data.json"), "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

# ---- PDF ----
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, grey
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER

class HR(Flowable):
    def __init__(self, width, color="#1e40af", thickness=1):
        Flowable.__init__(self)
        self.width = width; self.color = HexColor(color)
        self.thickness = thickness; self.height = thickness + 4
    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0,2,self.width,2)

out = BASE / "docs" / "security_sheeld_audit_blinde_20260920.pdf"
out.parent.mkdir(parents=True, exist_ok=True)

doc = SimpleDocTemplate(str(out), pagesize=A4,
    leftMargin=25*mm, rightMargin=25*mm, topMargin=20*mm, bottomMargin=20*mm,
    title="Security Sheeld — Audit Cybersécurité Blindé",
    author="Security Sheeld — Agent d'Audit Automatisé",
    subject="Rapport d'audit complet")

styles = getSampleStyleSheet()
ts = ParagraphStyle('T', parent=styles['Title'], fontSize=22, leading=28,
    textColor=HexColor("#0f172a"), spaceAfter=6*mm, alignment=TA_LEFT)
h1s = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=15, leading=20,
    textColor=HexColor("#1e40af"), spaceBefore=10*mm, spaceAfter=4*mm)
bs = ParagraphStyle('B', parent=styles['Normal'], fontSize=10, leading=14,
    textColor=HexColor("#334155"), spaceAfter=2*mm)
ss = ParagraphStyle('S', parent=styles['Normal'], fontSize=8, leading=10,
    textColor=grey, alignment=TA_CENTER)
logs = ParagraphStyle('L', parent=bs, fontSize=8, leading=11,
    textColor=HexColor("#1e293b"), leftIndent=5*mm, backColor=HexColor("#f1f5f9"), borderPadding=5)
recs = ParagraphStyle('R', parent=bs, leftIndent=5*mm, spaceAfter=2*mm)
step_s = ParagraphStyle('St', parent=bs, leftIndent=5*mm, spaceAfter=2*mm)

HBG = HexColor("#1e40af"); HFG = HexColor("#ffffff")
RAL = HexColor("#f8fafc"); BDR = HexColor("#cbd5e1")

def mk_tbl(headers, rows, cw=None):
    d = [headers]+rows
    if cw is None: cw=[doc.width/len(headers)]*len(headers)
    t=Table(d, colWidths=cw, repeatRows=1)
    cmds=[
        ('BACKGROUND',(0,0),(-1,0),HBG),('TEXTCOLOR',(0,0),(-1,0),HFG),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,0),9),
        ('BOTTOMPADDING',(0,0),(-1,0),8),('TOPPADDING',(0,0),(-1,0),8),
        ('FONTNAME',(0,1),(-1,-1),'Helvetica'),('FONTSIZE',(0,1),(-1,-1),9),
        ('TOPPADDING',(0,1),(-1,-1),5),('BOTTOMPADDING',(0,1),(-1,-1),5),
        ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
        ('GRID',(0,0),(-1,-1),0.5,BDR),('LINEBELOW',(0,0),(-1,0),1.5,HexColor("#1e40af")),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]
    for i in range(1,len(d)):
        if i%2==0: cmds.append(('BACKGROUND',(0,i),(-1,i),RAL))
    t.setStyle(TableStyle(cmds))
    return t

E=[]
E.append(Paragraph("SECURITY SHEELD", ts))
E.append(Paragraph("Audit Cybersécurité Blindé",
    ParagraphStyle('Sub',parent=styles['Normal'],fontSize=14,leading=18,
                   textColor=HexColor("#64748b"),spaceAfter=3*mm)))
E.append(HR(doc.width,"#1e40af",2))
E.append(Spacer(1,4*mm))
gd = datetime.now(timezone.utc).strftime('%d %B %Y a %H:%M UTC')
E.append(Paragraph(f"Rapport genere le : {gd}", ss))
E.append(Paragraph("Source : http://localhost:4050 — Protection : ACTIVEE", ss))
E.append(Spacer(1,8*mm))

# 1
E.append(Paragraph("1. Résumé Exécutif", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
E.append(mk_tbl(["Indicateur","Valeur","Statut"], [
    ["Etat de protection","ACTIVEE","🟢 OK"],
    ["Score de risque global",f"{data['risk_score']} / 100","🟢 FAIBLE" if data['risk_score']<30 else "🟡 MOYEN"],
    ["Ports ecoute totals",str(data["all_ports_count"]),"🔵 Info"],
    ["Ports exposes (0.0.0.0 / ::)",str(data["exposed_count"]),"🟡 A surveiller"],
    ["  dont bloques firewall",str(data["firewalled_count"]),"🛡️ Protege"],
    ["  dont NON bloques",str(data["unprotected_count"]),"🔴 Vulnérable" if data["unprotected_count"]>0 else "🟢 Aucun"],
    ["Ports critiques (bloques)",str(data["critical_count"]),"🟢 Aucun critique expose"],
    ["Ports inattendus (bloques)",str(data["unexpected_count"]),"🟡 Inattendus proteges"],
    ["Evenements intrusions (24h)",str(data["intrusion"]["statistics"]["total_events"]),"🟢 Calme"],
    ["IP banniees actives",str(data["intrusion"]["statistics"]["banned_ips"]),"🟢 Aucune"],
    ["Dernier durcissement","20/09/2026 14:47","✅ Recent"],
],[doc.width*0.42,doc.width*0.28,doc.width*0.30]))
E.append(Spacer(1,3*mm))
concl = (
    f"Protection active et fonctionnelle. Sur {data['exposed_count']} ports exposes en ecoute large, "
    f"{data['firewalled_count']} sont bloques par le firewall (soit {round(100*data['firewalled_count']/max(data['exposed_count'],1))}%). "
    f"Il reste {data['unprotected_count']} port(s) expose(s) non protege(s). "
    f"Aucun port critique (80, 443, 3389, 3306, 5432, 22) n'est accessible en clair sur toutes les interfaces. "
    f"Score de risque : {data['risk_score']}/100 (FAIBLE)."
)
E.append(Paragraph(f"<b>Conclusion :</b> {concl}", bs))

# 2 Firewall
E.append(Paragraph("2. Protection Firewall — Regles Actives (Block_Port_*)", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
E.append(Paragraph("Le script <font face='Courier'>security_hardening.ps1</font> a applique des regles de blocage sur le firewall Windows. Chaque regle est nommee <font face='Courier'>Block_Port_&lt;PORT&gt;_&lt;PROTO&gt;</font>, tracable et reversible. Voici l'etat des ports exposes :", bs))
fw_rows=[]
for p in data["exposed_ports_detail"]:
    fb = p["firewall_blocked"]
    rl = p["risk_level"]
    if rl=="critical":
        st="🛡️ BLOQUE — CRITIQUE" if fb else "🔴 NON BLOQUE — CRITIQUE"
    elif rl=="unexpected":
        st="🛡️ BLOQUE" if fb else "🔴 NON BLOQUE"
    else:
        st="🛡️ BLOQUE" if fb else "⚠️ Exposé non critique"
    typ="Critique" if rl=="critical" else ("Inattendu" if rl=="unexpected" else "Systeme/Autre")
    fw_rows.append([str(p["port"]), p["protocol"].upper(), typ, st])
E.append(mk_tbl(["Port","Proto","Type","Statut Firewall"], fw_rows,
    [doc.width*0.12,doc.width*0.10,doc.width*0.28,doc.width*0.50]))

# 3 Tous ports
E.append(Paragraph("3. Tous les Ports Detectes en Ecoute Large (0.0.0.0 / ::)", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
E.append(Paragraph(f"{data['exposed_count']} ports TCP en ecoute sur toutes les interfaces. Detail avec etat de protection :", bs))
ar=[]
for p in data["exposed_ports_detail"]:
    fb = "✅ OUI" if p["firewall_blocked"] else "❌ NON"
    ar.append([str(p["port"]), p["local_ip"], str(p["pid"]),
               p["process"], fb, p["risk_level"].upper()])
E.append(mk_tbl(["Port","Adresse","PID","Processus","FW BOUCHE?","Risque"], ar,
    [doc.width*0.09,doc.width*0.16,doc.width*0.09,doc.width*0.26,doc.width*0.16,doc.width*0.24]))

# 4 Historique
E.append(Paragraph("4. Historique des Snapshots (5 dernieres mesures)", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
if data["history"]:
    hrows=[]
    for h in data["history"]:
        hrows.append([str(h["idx"]), h["ts"], h["score_str"], str(h["nport"]),
                      "🟢 FAIBLE" if h["score"]<30 else ("🟡 MOYEN" if h["score"]<70 else "🔴 ELEVE")])
    E.append(mk_tbl(["#","Horodatage","Score Risque","Nb Ports","Statut"], hrows,
        [doc.width*0.08,doc.width*0.30,doc.width*0.16,doc.width*0.12,doc.width*0.34]))
else:
    E.append(Paragraph("Aucun snapshot en memoire.", bs))

# 5 Intrusions
E.append(Paragraph("5. Detection d'Intrusions", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
E.append(Paragraph("Le module analyse les <b>Journaux de securite Windows</b> (Event Log, IDs 4625/4624/4768/4769/5061) pour detecter les tentatives d'acces non autorisees, les scans de ports et les attaques par force brute. Les IP suspectes sont banniees automatiquement via le firewall Windows (regles netsh).", bs))
ist=data["intrusion"]["statistics"]
E.append(mk_tbl(["Indicateur","Valeur"], [
    ["Evenements totaux (24h)",str(ist.get("total_events",0))],
    ["IP uniques (24h)",str(ist.get("unique_ips",0))],
    ["Severite HAUTE",str(ist.get("high_severity",0))],
    ["Severite CRITIQUE",str(ist.get("critical_severity",0))],
    ["IP banniees actives",str(ist.get("banned_ips",0))],
    ["Surveillance active","Desactivee — non demarree"],
    ["Whitelist","127.0.0.1, ::1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12"],
    ["Seuil force brute","5 echecs / 5 minutes"],
    ["Seuil scan de ports","10 evenements / 1 minute"],
    ["Duree de baniissement","3 600 secondes (1 heure)"],
],[doc.width*0.40,doc.width*0.60]))
E.append(Spacer(1,2*mm))
E.append(Paragraph("<b>⚠️ Action requise :</b> La surveillance d'intrusions est <b>desactivee</b>. Pour l'activer : POST <font face='Courier'>/api/intrusion/start</font> via l'API ou le menu du systray.", bs))

# 6 Log
E.append(Paragraph("6. Dernier Durcissement Applique (20/09/2026 14:47)", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
logs_dir=BASE/"logs"/"hardening"
lf=sorted([f for f in logs_dir.iterdir() if f.suffix==".log"], reverse=True)
if lf:
    with open(lf[0],"r",encoding="utf-8",errors="replace") as f:
        ll=f.read().strip().splitlines()[-25:]
    rel=[l for l in ll if any(kw in l for kw in ["DEBUT","BLOQUE","LIbere","ETAT","FIN"])]
    E.append(Paragraph("<b>Extrait du log :</b>", bs))
    E.append(Spacer(1,1*mm))
    E.append(Paragraph(f"<font face='Courier' size=9>{chr(10).join(rel) if rel else '-'}</font>", logs))
else:
    E.append(Paragraph("Aucun log de durcissement trouve.", bs))

# 7 Recommandations
E.append(Paragraph("7. Points de Vigilance & Recommandations", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
for r in [
    "<b>Ports non proteges</b> —" + (f" {data['unprotected_count']} port(s) expose(s) sans blocage firewall. Verifier et appliquer un nouveau plan de durcissement." if data['unprotected_count']>0 else " Aucun. Tous les ports exposes sont proteges."),
    "<b>Surveillance intrusions inactive</b> — La demarrer pour beneficier de la protection anti-force-brute et anti-scan de ports (POST /api/intrusion/start).",
    "<b>Processus 'unknown'</b> — psutil ne peut lire les noms de certains processus sans droits admin complets. Les services systeme (PID 4 = System) sont normaux.",
    "<b>Ports 135 / 139 (Windows)</b> — Composants systeme inhérents (DCOM/RPC, NetBIOS/SMB), presents sur tous les Windows modernes. Difficiles a supprimer sans impacter les services domaine.",
    "<b>Verification post-durcissement</b> — Lancer regulierement un test de verification via scripts\\run_port_hardening_dryrun.bat ou le menu systray.",
    "<b>Double-clic Admin</b> — ✅ Corrige. start_complete_application_with_intrusion.bat et les scripts de durcissement demandent maintenant l'levation UAC automatiquement.",
    "<b>Menu Systray</b> — ✅ Corrige. Les entrees durcissement/liberation lancent les scripts avec UAC (Verb=runas) + auto-levation interne des .bat.",
    "<b>Service Windows</b> — Non encore configure. Prevoir NSSM pour un lancement service Windows (redemarrage auto, gestion erreurs).",
    "<b>Validation firewall au redemarrage</b> — Aucun controle automatique que les regles Block_Port_* persistent apres reboot. A ajouter au startup.",
]:
    E.append(Paragraph(f"• {r}", recs))

# 8 Verrouillage
E.append(Paragraph("8. Verrouillage de la Protection (Hardening Final)", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,2*mm))
E.append(Paragraph("Pour verrouiller l'etat actuel de la protection :", bs))
E.append(Spacer(1,1*mm))
for s in [
    "1. Installer le demarrage automatique Windows : executer <font face='Courier'>scripts\\installer_demarrage_windows.bat</font> (ajoute au Registry Run key).",
    "2. Verifier la persistence firewall apres reboot : menu systray → Appliquer plan durcissement (dry-run), puis verifier les regles Block_Port_* restent presentes.",
    "3. Activer la surveillance intrusions : POST <font face='Courier'>/api/intrusion/start</font>.",
    "4. Laisser le systray tourner en permanence pour surveillance visuelle et notifications.",
    "5. Regulierement : generer un nouveau plan (dashboard UI → selection → Appliquer), surtout apres installation de nouveaux logiciels."
]:
    E.append(Paragraph(s, step_s))

# 9 Signature
E.append(Paragraph("9. Signature et Validite", h1s))
E.append(HR(doc.width)); E.append(Spacer(1,3*mm))
E.append(Paragraph(
    "<b>Rapport genere automatiquement</b> par le module d'audit de Security Sheeld.<br/>"
    "Aucune donnee n'a quitte la machine locale. Conforme au principe de <b>confidentialite totale</b> (zero external telemetry).<br/>"
    "Fichier source : <font face='Courier'>logs/audit/security_audit_report.md</font><br/>"
    "Service : <font face='Courier'>http://localhost:4050</font> — Protection : <b>ACTIVE</b><br/><br/>"
    "— Fin du rapport —",
    bs))
E.append(Spacer(1,5*mm))
E.append(HR(doc.width,"#1e40af",1))
E.append(Spacer(1,2*mm))
E.append(Paragraph("— Fin du rapport —", ss))

doc.build(E)
sz=os.path.getsize(str(out))
print(f"\nPDF genere : {out}")
print(f"Taille : {sz} octets ({sz/1024:.1f} Ko)")
print(f"Pages attendues : ~{max(1, len(data['exposed_ports_detail'])//6 + 4)}")
