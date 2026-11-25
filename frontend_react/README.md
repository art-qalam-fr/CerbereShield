# Cerbere Security Shield — prototype React Browser

Prototype Phase 1 de la migration UI React/Tauri décrite dans `../PRD_Amélioration/PRD_UI_React_Desktop_Browser.md`.

## Commandes

```powershell
npm install
npm run dev
npm run lint
npm run build
```

Le serveur Vite proxy les appels `/api` et `/static` vers `http://localhost:4050`.

## Statut

- Le dashboard HTML actuel reste l'interface de production et n'est pas remplacé.
- Ce prototype reproduit le bandeau, la navigation, les états backend, les ports et les paramètres.
- Les autres onglets affichent un placeholder jusqu'à leur migration paritaire.
- Tauri et les modes Desktop/Both ne sont pas encore implémentés.
