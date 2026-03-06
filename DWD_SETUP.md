# Configuration Domain-Wide Delegation (DWD) pour Google Workspace MCP

Ce document explique comment configurer le MCP Google Workspace pour utiliser uniquement Service Account avec Domain-Wide Delegation, sans OAuth interactif.

## Vue d'ensemble

Ce MCP utilise **uniquement** Service Account avec Domain-Wide Delegation pour s'authentifier auprès des APIs Google Workspace. Toute la logique OAuth a été supprimée.

## Prérequis

1. Accès administrateur Google Workspace
2. Accès à Google Cloud Console
3. Service Account avec Domain-Wide Delegation activée

## Étape 1 : Créer un Service Account

1. Allez dans [Google Cloud Console](https://console.cloud.google.com/)
2. Sélectionnez votre projet (ou créez-en un)
3. Naviguez vers **IAM & Admin** > **Service Accounts**
4. Cliquez sur **Create Service Account**
5. Remplissez les informations :
   - **Name** : `google-workspace-mcp` (ou autre nom)
   - **Description** : `Service Account for Google Workspace MCP`
6. Cliquez sur **Create and Continue**
7. **Étape 2** : Attribuez le rôle "Service Account User" (ou laissez vide)
8. Cliquez sur **Done**

## Étape 2 : Activer Domain-Wide Delegation

1. Dans la liste des Service Accounts, cliquez sur celui que vous venez de créer
2. Allez dans l'onglet **Details**
3. Cliquez sur **Show Domain-Wide Delegation**
4. Cochez **Enable Google Workspace Domain-wide Delegation**
5. Notez le **Client ID** (vous en aurez besoin à l'étape 3)

## Étape 3 : Autoriser les scopes dans Google Admin Console

1. Allez dans [Google Admin Console](https://admin.google.com/)
2. Naviguez vers **Security** > **API Controls** > **Domain-wide Delegation**
3. Cliquez sur **Add new**
4. Remplissez :
   - **Client ID** : Le Client ID de votre Service Account (étape 2)
   - **OAuth Scopes** : Collez les scopes suivants (un par ligne) :

```
https://www.googleapis.com/auth/drive
https://www.googleapis.com/auth/documents
https://www.googleapis.com/auth/spreadsheets
https://www.googleapis.com/auth/userinfo.email
```

5. Cliquez sur **Authorize**

## Étape 4 : Générer une clé JSON

1. Retournez dans Google Cloud Console > Service Accounts
2. Cliquez sur votre Service Account
3. Allez dans l'onglet **Keys**
4. Cliquez sur **Add Key** > **Create new key**
5. Sélectionnez **JSON**
6. Cliquez sur **Create**
7. Le fichier JSON sera téléchargé - **garde-le en sécurité !**

## Étape 5 : Configurer les variables d'environnement

### Option A : Utiliser GOOGLE_SERVICE_ACCOUNT_JSON (recommandé)

```bash
export GOOGLE_SERVICE_ACCOUNT_JSON='{"type":"service_account","project_id":"...","private_key_id":"...","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n","client_email":"...@....iam.gserviceaccount.com","client_id":"...","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"..."}'
```

### Option B : Utiliser GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY

```bash
export GOOGLE_CLIENT_EMAIL="votre-service-account@votre-projet.iam.gserviceaccount.com"
export GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
```

**Note** : Pour `GOOGLE_PRIVATE_KEY`, vous devez inclure les `\n` littéraux dans la clé, ou utiliser des vraies nouvelles lignes si votre shell le supporte.

## Étape 6 : Configurer l'email d'impersonation

Configurez l'email Google à impersonner via Domain-Wide Delegation :

```bash
export GOOGLE_IMPERSONATE_EMAIL="administrateur@votre-domaine.com"
```

**Important** : 
- Cet email doit être dans votre domaine Google Workspace et avoir les permissions nécessaires pour accéder aux ressources Drive/Docs/Sheets que vous souhaitez utiliser.
- **Validation au startup** : Le serveur valide automatiquement que `GOOGLE_IMPERSONATE_EMAIL` est présent et a un format valide (contient "@") au démarrage. Si absent ou invalide, le serveur refuse de démarrer avec un message d'erreur clair (`RuntimeError: GOOGLE_IMPERSONATE_EMAIL missing...`).

### Configuration des templates (optionnel)

Si vous utilisez les outils de templates (`list_templates`, `duplicate_template`, etc.), vous pouvez configurer un dossier bot :

```bash
# Dossier bot contenant le sous-dossier "Templates" (fallback dev uniquement)
export BOT_FOLDER_ID="1a2b3c4d5e6f7g8h9i0j"
```

**Note** : En production, `bot_folder_id` doit être fourni à chaque appel des tools templates. `BOT_FOLDER_ID` est un fallback pour le développement uniquement.

**Fonctionnement** :
- Les tools templates résolvent automatiquement `BOT/Templates` à partir de `bot_folder_id`
- Si `folder_id` ou `template_id` est fourni directement, il est utilisé tel quel (mode expert/legacy)

### Comment obtenir un Drive Folder ID

1. Ouvrez Google Drive
2. Naviguez vers le dossier
3. L'URL sera : `https://drive.google.com/drive/folders/FOLDER_ID`
4. Copiez le `FOLDER_ID` de l'URL

## Étape 7 : Tester la configuration

### Test 1 : Vérifier les credentials Service Account

```python
from auth.service_account import get_service_account_credentials

credentials = get_service_account_credentials(
    required_scopes=["https://www.googleapis.com/auth/drive.readonly"]
)
print("✅ Service Account credentials OK")
```

### Test 2 : Tester l'authentification avec DWD

```python
from auth.service_account import get_authenticated_google_service

service, user_email = await get_authenticated_google_service(
    service_name="drive",
    version="v3",
    user_google_email="beatus@votre-domaine.com",
    required_scopes=["https://www.googleapis.com/auth/drive.readonly"],
    tool_name="test"
)
print(f"✅ Authentification OK pour {user_email}")
```

### Test 3 : Tester les templates

1. Créez un dossier "BOT" dans Drive avec un sous-dossier "Templates"
2. Ajoutez un template Google Doc dans "BOT/Templates"
3. Appelez `list_templates` avec `bot_folder_id` → doit lister les templates
4. Appelez `duplicate_template` avec `template_name` → doit dupliquer le template par nom

## Scopes exacts utilisés

Les scopes suivants doivent être autorisés dans Google Admin Console :

| Scope | Usage |
|-------|-------|
| `https://www.googleapis.com/auth/drive` | Accès complet à Google Drive (lecture/écriture) |
| `https://www.googleapis.com/auth/drive.readonly` | Lecture seule de Google Drive (si vous préférez) |
| `https://www.googleapis.com/auth/documents` | Accès à Google Docs (lecture/écriture) |
| `https://www.googleapis.com/auth/spreadsheets` | Accès à Google Sheets (lecture/écriture) |
| `https://www.googleapis.com/auth/userinfo.email` | Validation de l'email utilisateur |

**Note** : Si vous utilisez uniquement `drive.readonly`, certains outils en écriture ne fonctionneront pas.

## Variables d'environnement complètes

```bash
# Service Account (Option A ou B - REQUIS)
export GOOGLE_SERVICE_ACCOUNT_JSON='{...}'
# OU
export GOOGLE_CLIENT_EMAIL="..."
export GOOGLE_PRIVATE_KEY="..."

# Email d'impersonation (REQUIS)
export GOOGLE_IMPERSONATE_EMAIL="administrateur@votre-domaine.com"

# Templates (optionnel - fallback dev uniquement)
export BOT_FOLDER_ID="1a2b3c4d5e6f7g8h9i0j"  # Fallback pour bot_folder_id dans templates

# Debug (optionnel)
export ENABLE_DEBUG="true"  # Active /debug/headers endpoint
```

## Configuration simple

Le MCP fonctionne avec **un seul contexte d'impersonation** :
- Tous les services Google utilisent `GOOGLE_IMPERSONATE_EMAIL` pour l'impersonation via Domain-Wide Delegation
- Aucun cloisonnement interne : les restrictions métier sont gérées en amont (Dust/Make/prompt)
- Les tools accèdent librement à Drive/Docs/Sheets/Templates selon les paramètres fournis

## Système Templates (sans IDs)

Les tools templates fonctionnent par **navigation logique** dans Google Drive :

1. **Résolution automatique** : `BOT/Templates` est résolu automatiquement à partir de `bot_folder_id`
2. **Recherche par nom** : Les templates sont trouvés par nom (match exact puis contains)
3. **Support legacy** : Si `folder_id` ou `template_id` est fourni directement, il est utilisé tel quel (mode expert)

**Exemple** :
- `bot_folder_id = "1a2b3c4d5e6f7g8h9i0j"` (dossier BOT)
- Le système cherche automatiquement un sous-dossier "Templates" dans BOT
- `list_templates` liste les fichiers dans `BOT/Templates`
- `duplicate_template` trouve le template par nom dans `BOT/Templates`

## Dépannage

### Erreur : "Service Account credentials not configured"

- Vérifiez que `GOOGLE_SERVICE_ACCOUNT_JSON` ou `GOOGLE_CLIENT_EMAIL` + `GOOGLE_PRIVATE_KEY` sont définis
- Vérifiez que le JSON est valide (si vous utilisez GOOGLE_SERVICE_ACCOUNT_JSON)

### Erreur : "GOOGLE_IMPERSONATE_EMAIL missing"

- Vérifiez que `GOOGLE_IMPERSONATE_EMAIL` est défini
- Vérifiez que l'email est valide et dans le domaine Google Workspace

### Erreur : "OAuth authentication is not supported"

- C'est normal ! Ce MCP n'utilise pas OAuth
- Vérifiez que vous avez bien configuré Service Account (voir ci-dessus)

### Erreur : "Drive API authentication failed (401/403)"

- Vérifiez que Domain-Wide Delegation est activée dans Google Cloud Console
- Vérifiez que les scopes sont correctement autorisés dans Google Admin Console
- Vérifiez que le Service Account a les permissions nécessaires
- Consultez les logs pour voir `service_account_client_email`, `subject`, et `scopes` utilisés

### Erreur : "Templates folder 'Templates' not found under bot folder"

- Vérifiez que `bot_folder_id` pointe vers un dossier BOT valide
- Créez un sous-dossier "Templates" dans le dossier BOT
- Ou utilisez `folder_id` directement (mode expert/legacy)

## Tests manuels recommandés

1. **Lister fichiers** : `list_drive_items` avec n'importe quel `folder_id`
2. **Lister templates** : `list_templates` avec `bot_folder_id` → doit résoudre `BOT/Templates`
3. **Dupliquer template** : `duplicate_template` avec `template_name` → doit trouver par nom
4. **Remplacer variables** : `fill_template_variables` avec `{{VARIABLE}}` dans le doc
5. **Exporter PDF** : `export_pdf` avec `document_name_or_id` → doit trouver par nom ou ID

## Debug et monitoring

### Endpoint /debug/headers

Pour inspecter les headers reçus et le contexte résolu, activez le mode debug :

```bash
export ENABLE_DEBUG="true"
```

Puis accédez à :
- **HTTP endpoint** : `GET http://localhost:8000/debug/headers`
- **MCP tool** : `debug_headers()`

**Retour** :
```json
{
  "headers": {
    "X-End-User-Id": "tg:123456789",
    "X-Request-Id": "abc-123-def"
  },
  "context": {
    "end_user_id": "tg:123456789",
    "request_id": "abc-123-def"
  }
}
```

**Note** : Les headers peuvent être `null` s'ils ne sont pas présents. Le contexte retourne toujours des valeurs (par défaut `"unknown"` si non défini).

### Logs d'authentification

Les logs d'authentification incluent maintenant :
- `[AUTH] service_account_client_email=...` : Email du Service Account
- `subject=...` : Email de l'utilisateur impersonné (DWD)
- `scopes=[...]` : Scopes OAuth utilisés

**Important** : La `private_key` n'est **jamais** loggée pour des raisons de sécurité.

## Support

Pour plus d'informations, consultez :
- [Google Cloud Service Accounts](https://cloud.google.com/iam/docs/service-accounts)
- [Domain-Wide Delegation](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)

