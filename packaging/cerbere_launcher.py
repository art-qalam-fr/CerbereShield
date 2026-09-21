"""Point d'entrée de l'exécutable packagé Cerbere Security Shield.

Lance le backend FastAPI/uvicorn sur localhost:4050 puis ouvre le
navigateur par défaut sur le dashboard. En mode frozen (PyInstaller),
stdout/stderr sont redirigés vers ``logs/launcher.log`` car il n'y a
pas de console attachée.
"""

import sys
import threading
import webbrowser


def main() -> None:
    import cerbere_paths as paths

    # Pré-création des dossiers inscriptibles (%LOCALAPPDATA%\CerbereShield)
    logs = paths.logs_dir()
    paths.state_dir()

    # En mode fenêtré (console=False) stdout/stderr peuvent être None :
    # on redirige vers un fichier pour conserver la capacité de debug.
    if paths.is_frozen():
        try:
            log_file = open(logs / "launcher.log", "a", encoding="utf-8", buffering=1)
            sys.stdout = sys.stderr = log_file
        except OSError:
            pass

    print("[Cerbere] Demarrage du backend sur http://localhost:4050 ...")
    print(f"[Cerbere] frozen={paths.is_frozen()} data={paths.data_root()}")

    import uvicorn
    import web_port_dashboard.port_dashboard as dashboard

    server = uvicorn.Server(
        uvicorn.Config(dashboard.app, host="localhost", port=4050, reload=False)
    )
    # Référence partagée : permet l'arrêt propre via /api/shutdown
    dashboard._uvicorn_server = server

    threading.Timer(1.5, lambda: webbrowser.open("http://localhost:4050/")).start()

    try:
        server.run()
    except OSError as e:
        # Port déjà occupé : une instance tourne probablement déjà —
        # on ouvre quand même le navigateur vers le dashboard existant.
        print(f"[Cerbere] Port 4050 indisponible ({e}) — ouverture du navigateur.")
        webbrowser.open("http://localhost:4050/")


if __name__ == "__main__":
    main()
