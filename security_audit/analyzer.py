"""
Analyseur de risques de sécurité
Évalue les vulnérabilités et génère des recommandations
"""

from typing import Dict, List, Any

class SecurityAnalyzer:
    """Classe pour analyser les risques de sécurité"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.debug = config.get('debug', False)
        self.critical_ports = set(config.get('critical_ports', [22, 80, 443, 3389, 3306, 5432]))
        self.allowed_ports = config.get('allowed_ports', [])

    def analyze_risks(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse les données réseau et retourne les résultats d'analyse
        """
        if self.debug:
            print("Démarrage de l'analyse des risques...")

        ports = network_data.get('ports', [])
        exposed_ports = network_data.get('exposed_ports', [])

        # Analyse des expositions
        critical_exposed = self._check_critical_ports(exposed_ports)
        unexpected_exposed = self._check_unexpected_ports(exposed_ports)

        # Calcul du score de risque (pourcentage de ports réellement dangereux par rapport à tous les ports détectés)
        risk_score = self._calculate_risk_score(ports, exposed_ports, critical_exposed, unexpected_exposed)

        # Génération des recommandations
        recommendations = self._generate_recommendations(exposed_ports, critical_exposed, unexpected_exposed)

        results = {
            'risk_score': risk_score,
            'critical_exposed': critical_exposed,
            'unexpected_exposed': unexpected_exposed,
            'total_exposed': len(exposed_ports),
            'recommendations': recommendations,
            'summary': self._create_summary(risk_score, len(exposed_ports), len(critical_exposed))
        }

        if self.debug:
            print(f"Analyse terminée: score de risque = {risk_score}")

        return results

    def _check_critical_ports(self, exposed_ports: List[Dict]) -> List[Dict]:
        """Vérifie si des ports critiques sont exposés"""
        critical = []
        for port in exposed_ports:
            if port.get('port') in self.critical_ports:
                port['risk_level'] = 'critical'
                critical.append(port)
        return critical

    def _check_unexpected_ports(self, exposed_ports: List[Dict]) -> List[Dict]:
        """Vérifie les ports exposés non autorisés"""
        unexpected = []
        allowed_port_numbers = {p.get('port') for p in self.allowed_ports}

        for port in exposed_ports:
            port_num = port.get('port')
            if port_num not in allowed_port_numbers:
                port['risk_level'] = 'unexpected'
                unexpected.append(port)

        return unexpected

    def _calculate_risk_score(
        self,
        all_ports: List[Dict],
        exposed_ports: List[Dict],
        critical: List[Dict],
        unexpected: List[Dict],
    ) -> int:
        """Calcule un score de risque sur 100 en pourcentage simple.

        - Numérateur : nombre de ports réellement dangereux exposés
          (critiques ou inattendus, donc *à la fois* exposés ET non bloqués FW).
        - Dénominateur : nombre total de ports détectés (toutes écoutes confondues).
        """

        def _key(port: Dict[str, Any]) -> tuple:
            return (
                port.get('port'),
                port.get('protocol') or port.get('proto'),
                port.get('local_ip') or port.get('ip'),
            )

        # On travaille uniquement sur les ports encore exposés
        exposed_keys = {_key(p) for p in exposed_ports}

        # Ports critiques ou inattendus exposés (union, sans double comptage)
        dangerous_keys = set()
        for p in critical + unexpected:
            k = _key(p)
            if k in exposed_keys:
                dangerous_keys.add(k)

        dangerous_count = len(dangerous_keys)
        total_ports = len(all_ports) or 1

        # Pourcentage de ports dangereux parmi tous les ports détectés
        percent = int(round(100 * dangerous_count / total_ports))
        return max(0, min(100, percent))

    def _generate_recommendations(self, exposed_ports: List[Dict], critical: List[Dict], unexpected: List[Dict]) -> List[str]:
        """Génère des recommandations de durcissement"""
        recommendations = []

        if critical:
            recommendations.append("🚨 PORTS CRITIQUES EXPOSÉS - Action immédiate requise:")
            for port in critical:
                recommendations.append(f"   - Port {port['port']} ({port['protocol']}) est critique et exposé")

        if unexpected:
            recommendations.append("⚠️ PORTS INATTENDUS EXPOSÉS:")
            for port in unexpected:
                process_name = port.get('process', {}).get('name', 'unknown')
                recommendations.append(f"   - Port {port['port']} ({process_name}) - vérifier si nécessaire")

        if exposed_ports:
            recommendations.append("🔒 RECOMMANDATIONS GÉNÉRALES:")
            recommendations.append("   - Limitez l'écoute aux adresses locales (127.0.0.1) quand possible")
            recommendations.append("   - Utilisez un firewall pour bloquer les ports inutiles")
            recommendations.append("   - Vérifiez régulièrement les services en cours")

        if not exposed_ports:
            recommendations.append("✅ AUCUN PORT EXPOSÉ - Bonne configuration de sécurité")

        return recommendations

    def _create_summary(self, risk_score: int, total_exposed: int, critical_count: int) -> str:
        """Crée un résumé textuel de l'analyse"""
        if risk_score < 30:
            level = "FAIBLE"
        elif risk_score < 70:
            level = "MOYEN"
        else:
            level = "ÉLEVÉ"

        return f"Niveau de risque: {level} (Score: {risk_score}/100) - {total_exposed} ports exposés, {critical_count} critiques"
