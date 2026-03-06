# Variables d'environnement - Configuration Scaleway et Dust

Ce document liste toutes les variables d'environnement nécessaires pour déployer le MCP Google Workspace sur Scaleway et l'utiliser avec Dust.

## Variables pour Scaleway (où est hébergé le MCP)

### Service Account (requis - Option A ou B)

**Option A : JSON complet (recommandé)**
```bash
GOOGLE_SERVICE_ACCOUNT_JSON='{"type":"service_account","project_id":"...","private_key_id":"...","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n","client_email":"...@....iam.gserviceaccount.com","client_id":"...","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"..."}'
```

**Option B : Email + Clé privée**
```bash
GOOGLE_CLIENT_EMAIL="votre-service-account@votre-projet.iam.gserviceaccount.com"
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
```

### Email d'impersonation (requis)

```bash
GOOGLE_IMPERSONATE_EMAIL="administrateur@votre-domaine.com"
```

**Important** : 
- Cet email doit être dans votre domaine Google Workspace et avoir les permissions nécessaires pour accéder aux ressources Drive/Docs/Sheets.
- **Validation au startup** : Le serveur valide automatiquement que `GOOGLE_IMPERSONATE_EMAIL` est présent et a un format valide (contient "@") au démarrage. Si absent ou invalide, le serveur refuse de démarrer avec un message d'erreur clair.

### Templates (optionnel - fallback dev uniquement)

```bash
BOT_FOLDER_ID="1a2b3c4d5e6f7g8h9i0j"  # Fallback pour bot_folder_id dans templates (dev uniquement)
```

**Note** : En production, `bot_folder_id` doit être fourni à chaque appel des tools templates. `BOT_FOLDER_ID` est un fallback pour le développement uniquement.

### Debug (optionnel)

```bash
ENABLE_DEBUG="true"  # Active /debug/headers endpoint
```

## Headers pour Dust (où vous ne pouvez que rajouter des headers)

Dust peut envoyer les headers suivants dans chaque requête HTTP vers le MCP pour la traçabilité :

### Headers optionnels (pour la traçabilité)

```http
X-End-User-Id: user:123456
# OU (priorité si présent)
X-Telegram-User-Id: 123456789
# OU (fallback)
X-User-Id: user:123456

X-Request-Id: abc-123-def-456
```

**Normalisation** :
- `X-Telegram-User-Id` numérique → `tg:123456789`
- Autres → `user:<value>`
- Si aucun header → `unknown`

**Request ID** :
- Si `X-Request-Id` présent → utilisé tel quel
- Sinon → UUID v4 généré automatiquement

## Exemple de configuration complète

### Scaleway (variables d'environnement)

```bash
# Service Account (Option A ou B)
export GOOGLE_SERVICE_ACCOUNT_JSON='{...}'
# OU
export GOOGLE_CLIENT_EMAIL="..."
export GOOGLE_PRIVATE_KEY="..."

# Email d'impersonation (REQUIS)
export GOOGLE_IMPERSONATE_EMAIL="administrateur@domaine.com"

# Templates (optionnel - fallback dev uniquement)
export BOT_FOLDER_ID="1a2b3c4d5e6f7g8h9i0j"

# Debug (optionnel)
export ENABLE_DEBUG="true"
```

### Dust (headers HTTP)

```http
POST /mcp/tools/call
X-End-User-Id: tg:123456789
X-Request-Id: req-abc-123
```

**Note** : Les headers sont optionnels et utilisés uniquement pour la traçabilité. Le MCP fonctionne sans headers.

## Vérification

### Tester la configuration Scaleway

1. **Vérifier les credentials Service Account** :
   ```bash
   curl http://localhost:8000/health
   ```

2. **Tester le debug endpoint** (si `ENABLE_DEBUG=true`) :
   ```bash
   curl http://localhost:8000/debug/headers \
     -H "X-End-User-Id: tg:123456789"
   ```

### Tester depuis Dust

1. **Appeler un tool avec headers** :
   ```json
   {
     "tool": "list_drive_items",
     "arguments": {
       "folder_id": "BEATUS_DRIVE_FOLDER_ID"
     }
   }
   ```
   Headers (optionnels) :
   ```http
   X-End-User-Id: tg:123456789
   X-Request-Id: req-abc-123
   ```

2. **Vérifier les logs** :
   - Les logs doivent inclure `[AUTH] service_account_client_email=... subject=... scopes=[...]`
   - Les logs doivent inclure `[tool_start]` avec `end_user_id`, `request_id`

## Notes importantes

1. **Configuration simple** : Le MCP fonctionne avec un seul email d'impersonation (`GOOGLE_IMPERSONATE_EMAIL`). Aucun cloisonnement interne.

2. **Templates sans IDs** : Les tools templates fonctionnent par navigation logique (`BOT/Templates`) et recherche par nom. Les IDs ne sont plus nécessaires côté utilisateur.

3. **Support legacy** : Les paramètres `folder_id` et `template_id` sont toujours acceptés (mode expert) pour compatibilité.

4. **Logs d'auth** : Les logs incluent `service_account_client_email`, `subject`, et `scopes`, mais **jamais** la `private_key`.

5. **Debug headers** : L'endpoint `/debug/headers` retourne toujours les headers et le contexte, même s'ils sont absents (valeurs `null` ou `"unknown"`).

