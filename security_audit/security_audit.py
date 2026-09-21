#!/usr/bin/env python3
"""
Outil d'audit de sécurité PC/réseau
Point d'entrée CLI pour analyser les ports ouverts et les risques de sécurité
"""

import argparse
import sys
import os
from pathlib import Path

# Ajout du répertoire actuel au path pour importer les modules locaux
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from collector import NetworkCollector
from analyzer import SecurityAnalyzer
from reporter import ReportGenerator

def load_config(config_path: str = None) -> dict:
    """Charge la configuration depuis le fichier YAML"""
    import yaml

    if config_path is None:
        config_path = current_dir / "config.yml"
    else:
        config_path = Path(config_path)

    # Si config.yml n'existe pas, utiliser config.example.yml
    if not config_path.exists():
        example_config = current_dir / "config.example.yml"
        if example_config.exists():
            print(f"Configuration non trouvée, utilisation de {example_config}")
            config_path = example_config
        else:
            print("Erreur: Aucun fichier de configuration trouvé")
            sys.exit(1)

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Erreur lors du chargement de la configuration: {e}")
        sys.exit(1)

def main():
    """Fonction principale du programme"""
    parser = argparse.ArgumentParser(
        description="Outil d'audit de sécurité PC/réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python security_audit.py                    # Audit avec config par défaut
  python security_audit.py -c config.yml      # Spécifier un fichier de config
  python security_audit.py --verbose          # Mode verbeux
        """
    )

    parser.add_argument(
        '-c', '--config',
        type=str,
        help='Chemin vers le fichier de configuration'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mode verbeux'
    )

    args = parser.parse_args()

    print("🚀 Démarrage de l'audit de sécurité...")

    # Chargement de la configuration
    config = load_config(args.config)
    if args.verbose:
        config['debug'] = True

    if config.get('debug'):
        print(f"Configuration chargée: {config}")

    try:
        # Phase 1: Collecte des informations
        print("📡 Collecte des informations réseau...")
        collector = NetworkCollector(config)
        network_data = collector.collect_network_info()

        if config.get('debug'):
            print(f"Données collectées: {len(network_data.get('ports', []))} ports trouvés")

        # Phase 2: Analyse des risques
        print("🔍 Analyse des risques...")
        analyzer = SecurityAnalyzer(config)
        analysis_results = analyzer.analyze_risks(network_data)

        # Phase 3: Génération du rapport
        print("📄 Génération du rapport...")
        reporter = ReportGenerator(config)
        report_path = reporter.generate_report(network_data, analysis_results)

        print(f"✅ Audit terminé. Rapport généré: {report_path}")

        # Affichage du score de risque
        risk_score = analysis_results.get('risk_score', 0)
        if risk_score < 30:
            print("🟢 Score de risque: FAIBLE")
        elif risk_score < 70:
            print("🟡 Score de risque: MOYEN")
        else:
            print("🔴 Score de risque: ÉLEVÉ")

    except Exception as e:
        print(f"❌ Erreur lors de l'audit: {e}")
        if config.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
