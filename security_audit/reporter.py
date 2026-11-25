"""
Générateur de rapports de sécurité
Crée des rapports lisibles en Markdown ou HTML
"""

from typing import Dict, List, Any
from pathlib import Path

class ReportGenerator:
    """Classe pour générer les rapports d'audit"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.debug = config.get('debug', False)
        self.format = config.get('report', {}).get('format', 'markdown')
        self.output_file = config.get('report', {}).get('output_file', 'security_audit_report.md')
        self.include_details = config.get('report', {}).get('include_details', True)

    def generate_report(self, network_data: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """
        Génère le rapport complet
        """
        if self.debug:
            print("Génération du rapport...")

        report_content = self._build_report_content(network_data, analysis_results)

        # Création du fichier de rapport (chemin relatif résolu depuis la racine du projet,
        # pour correspondre à l'attente de scripts/powershell/port_monitoring.ps1)
        output_path = Path(self.output_file)
        if not output_path.is_absolute():
            output_path = Path(__file__).resolve().parents[1] / output_path
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)

            if self.debug:
                print(f"Rapport généré: {output_path.absolute()}")

            return str(output_path.absolute())

        except Exception as e:
            print(f"Erreur lors de la génération du rapport: {e}")
            return ""

    def _build_report_content(self, network_data: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """Construit le contenu du rapport"""
        lines = []

        # En-tête
        lines.append("# Rapport d'Audit de Sécurité PC/Réseau")
        lines.append("")
        lines.append(f"Généré le: {network_data.get('timestamp', 'N/A')}")
        lines.append("")

        # Résumé
        lines.append("## Résumé")
        lines.append("")
        summary = analysis_results.get('summary', 'Aucune analyse disponible')
        lines.append(f"**{summary}**")
        lines.append("")

        # Statistiques principales
        lines.append("### Statistiques")
        lines.append("")
        lines.append(f"- **Ports totaux détectés**: {network_data.get('total_ports', 0)}")
        lines.append(f"- **Ports exposés (0.0.0.0)**: {network_data.get('total_exposed', 0)}")
        lines.append(f"- **Ports critiques exposés**: {len(analysis_results.get('critical_exposed', []))}")
        lines.append(f"- **Ports inattendus exposés**: {len(analysis_results.get('unexpected_exposed', []))}")
        lines.append("")

        # Recommandations
        recommendations = analysis_results.get('recommendations', [])
        if recommendations:
            lines.append("## Recommandations")
            lines.append("")
            for rec in recommendations:
                lines.append(rec)
            lines.append("")

        # Détails des ports (si demandé)
        if self.include_details:
            lines.append("## Détails des Ports")
            lines.append("")
            self._add_ports_table(lines, network_data)

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Rapport généré automatiquement par l'outil d'audit de sécurité*")

        return "\n".join(lines)

    def _add_ports_table(self, lines: List[str], network_data: Dict[str, Any]):
        """Ajoute un tableau détaillé des ports"""
        ports = network_data.get('ports', [])

        if not ports:
            lines.append("Aucun port détecté.")
            return

        lines.append("| Port | Protocole | Adresse Locale | État | Processus | Exposition |")
        lines.append("|------|-----------|----------------|-------|-----------|------------|")

        for port in ports:
            port_num = port.get('port', 'N/A')
            protocol = port.get('protocol', 'N/A').upper()
            local_ip = port.get('local_ip', 'N/A')
            state = port.get('state', 'N/A')
            process_name = port.get('process', {}).get('name', 'unknown')

            # Indicateur d'exposition
            exposure = "❌ Non exposé"
            if local_ip in ['0.0.0.0', '*', '::']:
                exposure = "⚠️ Exposé"

            lines.append(f"| {port_num} | {protocol} | {local_ip} | {state} | {process_name} | {exposure} |")

        lines.append("")
