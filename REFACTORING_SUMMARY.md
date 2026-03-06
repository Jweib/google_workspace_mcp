# Résumé de la Refactorisation : Service Account + Domain-Wide Delegation

## Vue d'ensemble

Cette refactorisation a complètement supprimé toute la logique OAuth (2.0 et 2.1) du MCP Google Workspace et l'a remplacée par une authentification exclusive via Service Account avec Domain-Wide Delegation (DWD).

## Fichiers créés

1. **`auth/service_account.py`** : Module central pour l'authentification Service Account
   - `get_service_account_credentials()` : Charge les credentials depuis les variables d'environnement
   - `get_authenticated_google_service()` : Fonction unifiée pour obtenir un service Google authentifié avec DWD

2. **`auth/agent_context.py`** : Gestion du contexte agent
   - `get_agent_from_request()` : Détecte l'agent via header `X-Agent` ou contexte FastMCP
   - `get_agent_user_email()` : Résout l'email utilisateur pour l'agent
   - `get_agent_drive_folder_id()` : Résout le folder ID allowlist pour l'agent
   - `resolve_agent_context()` : Résout le contexte complet (agent, email, folder)

3. **`utils/drive_guard.py`** : Validation du cloisonnement Drive
   - `validate_drive_access()` : Valide que les opérations Drive sont dans l'allowlist
   - `validate_drive_query_access()` : Restreint les requêtes Drive à l'allowlist

4. **`DWD_SETUP.md`** : Documentation complète pour la configuration DWD

## Fichiers modifiés

### `auth/service_decorator.py`
- **Supprimé** : Toute la logique OAuth 2.1/2.0
  - `_detect_oauth_version()`
  - `get_authenticated_google_service_oauth21()`
  - `_extract_oauth21_user_email()`, `_extract_oauth20_user_email()`
  - `_override_oauth21_user_email()`
- **Ajouté** : 
  - `_resolve_agent_user_email()` : Résout l'email depuis le contexte agent
  - Utilisation exclusive de `auth.service_account.get_authenticated_google_service()`
- **Simplifié** : `require_google_service()` et `require_multiple_services()` utilisent uniquement Service Account

### `auth/google_auth.py`
- **Supprimé** : Toutes les fonctions OAuth
  - `start_auth_flow()`
  - `handle_auth_callback()` (2 implémentations)
  - `_legacy_start_auth_flow()`
  - `get_credentials()`
  - `create_oauth_flow()`
  - `load_client_secrets()`, `check_client_secrets()`
  - Toutes les fonctions de gestion de session OAuth
- **Conservé** :
  - `GoogleAuthenticationError` (exception)
  - `get_user_info()` (pour compatibilité, non utilisé en Service Account)
  - `get_authenticated_google_service()` (wrapper de compatibilité vers `auth.service_account`)

### `core/server.py`
- **Modifié** : Route `/oauth2callback` retourne maintenant 403 avec message clair
- **Supprimé** : Fonction `legacy_oauth2_callback()`
- **Amélioré** : Tool `start_google_auth` avec message explicatif Service Account uniquement

### `auth/mcp_session_middleware.py`
- **Ajouté** : Extraction du header `X-Agent` et stockage dans le contexte
- **Ajouté** : Stockage de l'agent dans FastMCP context state

### `auth/oauth_callback_server.py`
- **Supprimé** : Imports OAuth obsolètes (`handle_auth_callback`, `check_client_secrets`)
- **Conservé** : Route `/oauth2callback` bloquée (retourne 403)

### `gdrive/drive_tools.py`
- **Ajouté** : Import de `validate_drive_access` et `validate_drive_query_access`
- **Ajouté** : Validations dans tous les tools :
  - `search_drive_files` : Restriction de requête
  - `get_drive_file_content` : Validation file_id
  - `get_drive_file_download_url` : Validation file_id
  - `list_drive_items` : Validation folder_id
  - `create_drive_file` : Validation folder_id
  - `get_drive_file_permissions` : Validation file_id
  - `check_drive_file_public_access` : Validation file_id
  - `update_drive_file` : Validation file_id

### `gdocs/docs_tools.py`
- **Ajouté** : Import de `validate_drive_access` et `validate_drive_query_access`
- **Ajouté** : Validations dans les tools utilisant Drive API :
  - `search_docs` : Restriction de requête
  - `get_doc_content` : Validation document_id
  - `list_docs_in_folder` : Validation folder_id
  - `insert_doc_image` : Validation image_source (si file_id Drive)
  - `export_doc_to_pdf` : Validation document_id et folder_id

### `gsheets/sheets_tools.py`
- **Ajouté** : Import de `validate_drive_query_access`
- **Ajouté** : Validation dans `list_spreadsheets` : Restriction de requête

### `gtemplates/templates_tools.py`
- **Ajouté** : Import de `validate_drive_access`
- **Ajouté** : Validations dans tous les tools :
  - `list_templates` : Validation folder_id
  - `duplicate_template` : Validation template_id et destination_folder_id
  - `export_pdf` : Validation document_id et destination_folder_id

## Variables d'environnement requises

### Service Account (Option A ou B)
- `GOOGLE_SERVICE_ACCOUNT_JSON` : JSON complet du Service Account
- OU
- `GOOGLE_CLIENT_EMAIL` : Email du Service Account
- `GOOGLE_PRIVATE_KEY` : Clé privée du Service Account

### Agent Beatus
- `BEATUS_USER_EMAIL` : Email Google Workspace pour Beatus
- `BEATUS_DRIVE_FOLDER_ID` : Folder ID allowlist pour Beatus

### Agent Hildegarde
- `HILDEGARDE_USER_EMAIL` : Email Google Workspace pour Hildegarde
- `HILDEGARDE_DRIVE_FOLDER_ID` : Folder ID allowlist pour Hildegarde

## Scopes exacts pour DWD

Les scopes suivants doivent être autorisés dans Google Admin Console :

```
https://www.googleapis.com/auth/drive
https://www.googleapis.com/auth/documents
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/userinfo.email
```

## Détection de l'agent

L'agent est détecté via :
1. Header HTTP `X-Agent: beatus` ou `X-Agent: hildegarde`
2. FastMCP context state (si défini)
3. Défaut : `beatus` si aucun agent spécifié

## Sécurité : Cloisonnement

Chaque agent a accès **uniquement** à son dossier Drive désigné :
- Toute tentative d'accès hors allowlist est rejetée avec `DriveAccessDeniedError`
- Les requêtes Drive sont automatiquement restreintes au folder allowlist

## Tests manuels recommandés

1. **Lister fichiers** : `list_drive_items` dans le dossier allowlist
2. **Dupliquer template** : `duplicate_template` avec template dans dossier allowlist
3. **Remplacer variables** : `fill_template_variables` avec `{{VARIABLE}}`
4. **Vérifier formatage** : `get_doc_content` après remplacement
5. **Test cloisonnement** : Tenter accès hors dossier → doit être rejeté
6. **Test agent switching** : Vérifier que Beatus et Hildegarde ont des dossiers distincts

## Compatibilité

- ✅ Transport MCP (SSE/streamable-http) : Non modifié
- ✅ Tous les tools existants : Fonctionnent avec Service Account
- ❌ OAuth interactif : Complètement supprimé
- ✅ Backward compatibility : `get_authenticated_google_service()` dans `auth.google_auth` redirige vers `auth.service_account`

## Notes importantes

1. **Aucune dépendance OAuth** : Tous les imports et appels OAuth ont été supprimés
2. **Architecture claire** : Séparation nette entre Service Account, Agent Context, et Drive Guard
3. **Validation stricte** : Tous les accès Drive sont validés avant exécution
4. **Logging amélioré** : Tous les logs incluent le nom de l'agent et le tool

