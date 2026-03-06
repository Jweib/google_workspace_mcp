<div align="center">

# 🚀 Google Workspace MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/workspace-mcp.svg)](https://pypi.org/project/workspace-mcp/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/workspace-mcp?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=BLUE&left_text=pip%20downloads)](https://pepy.tech/projects/workspace-mcp)

**Serveur MCP complet pour contrôler Google Workspace via langage naturel**

*Contrôle total de Gmail, Calendar, Drive, Docs, Sheets, Slides, Forms, Tasks, Chat, Contacts, Apps Script, Custom Search et Templates grâce au protocole MCP*

[Documentation](#-documentation) • [Installation rapide](#-installation-rapide) • [Configuration](#-configuration) • [Contribuer](#-contribuer)

</div>

---

## 📋 Table des matières

- [Vue d'ensemble](#-vue-densemble)
- [Fonctionnalités](#-fonctionnalités)
- [Installation rapide](#-installation-rapide)
- [Configuration](#-configuration)
- [Architecture](#-architecture)
- [Documentation](#-documentation)
- [Développement](#-développement)
- [Sécurité](#-sécurité)
- [Contribuer](#-contribuer)
- [Licence](#-licence)

---

## 🎯 Vue d'ensemble

Le **Google Workspace MCP Server** est un serveur MCP (Model Context Protocol) production-ready qui permet d'intégrer tous les services Google Workspace avec des assistants IA. Il supporte l'authentification multi-utilisateurs via OAuth 2.1 et Service Account avec Domain-Wide Delegation.

### Cas d'usage principaux

- 🤖 **Assistants IA** : Intégration complète avec Claude, ChatGPT, et autres assistants via MCP
- 📧 **Automatisation Gmail** : Gestion des emails, envoi, recherche avancée
- 📅 **Gestion de calendrier** : Création d'événements, recherche, modifications
- 📁 **Opérations Drive** : Upload, téléchargement, recherche, gestion de fichiers
- 📝 **Création de documents** : Docs, Sheets, Slides avec édition complète
- 🔄 **Templates** : Système complet de templates Google Docs avec variables

---

## ✨ Fonctionnalités

### 📧 Gmail
- ✅ Recherche avancée avec opérateurs Gmail
- ✅ Lecture complète des messages (HTML, texte, pièces jointes)
- ✅ Envoi d'emails (HTML, CC, BCC, threading)
- ✅ Gestion des threads et conversations
- ✅ Gestion des labels et drafts
- ✅ Batch operations

### 📁 Google Drive
- ✅ Recherche avec syntaxe de requête Drive native
- ✅ Upload/Téléchargement de fichiers
- ✅ Support formats Office (.docx, .xlsx, .pptx)
- ✅ Gestion des permissions et partage
- ✅ Export PDF
- ✅ Opérations sur les dossiers

### 📝 Google Docs
- ✅ Création et édition de documents
- ✅ Gestion des tableaux (création, modification, formatage)
- ✅ Headers/Footers dynamiques
- ✅ Commentaires et réponses
- ✅ Insertion d'images
- ✅ Structure du document (sections, paragraphes)

### 📊 Google Sheets
- ✅ Création et modification de feuilles
- ✅ Gestion des cellules (valeur, formatage)
- ✅ Formules et fonctions
- ✅ Création de graphiques
- ✅ Batch operations
- ✅ Filtres et tri

### 📅 Google Calendar
- ✅ Création et gestion d'événements
- ✅ Recherche avancée
- ✅ Gestion des participants
- ✅ Récurrence et exceptions
- ✅ Multi-calendriers

### 🎨 Google Slides
- ✅ Création et modification de présentations
- ✅ Gestion des diapositives
- ✅ Insertion de texte et images
- ✅ Templates

### 📋 Google Forms
- ✅ Création de formulaires
- ✅ Gestion des réponses
- ✅ Paramètres de publication

### 💬 Google Chat
- ✅ Envoi de messages
- ✅ Gestion des espaces
- ✅ Threading

### ✅ Google Tasks
- ✅ Création et gestion de tâches
- ✅ Listes de tâches
- ✅ Hiérarchie et dépendances

### 👤 Google Contacts
- ✅ Recherche de contacts (nom, email, téléphone)
- ✅ Consultation détaillée d'un contact
- ✅ Création, modification et suppression de contacts
- ✅ Gestion des groupes de contacts (labels)
- ✅ Opérations batch (création/modification/suppression en masse)

### ⚡ Google Apps Script
- ✅ Lister et consulter les projets Apps Script
- ✅ Créer et modifier des projets de scripts
- ✅ Exécuter des fonctions de scripts
- ✅ Gestion des déploiements (créer, mettre à jour, supprimer)
- ✅ Gestion des versions
- ✅ Consultation des métriques d'exécution
- ✅ Génération de code de triggers

### 🔍 Custom Search
- ✅ Intégration Google Programmable Search Engine

### 🔐 Authentification & Sécurité
- ✅ **OAuth 2.0/2.1** : Support complet OAuth avec refresh automatique
- ✅ **Service Account + DWD** : Domain-Wide Delegation pour entreprises
- ✅ **Multi-utilisateurs** : Support authentification multi-utilisateurs
- ✅ **Sessions sécurisées** : Gestion automatique des tokens
- ✅ **Scope complet** : Utilisation du scope `drive` complet pour compatibilité DWD

---

## 🚀 Installation rapide

### Option 1 : Installation Claude Desktop (Recommandé)

1. **Télécharger** : Récupérez le fichier `google_workspace_mcp.dxt` depuis la page [Releases](https://github.com/taylorwilsdon/google_workspace_mcp/releases)
2. **Installer** : Double-cliquez sur le fichier → Claude Desktop s'ouvre et propose d'installer
3. **Configurer** : Dans Claude Desktop → **Settings → Extensions → Google Workspace MCP**, collez vos identifiants Google OAuth
4. **Utiliser** : Démarrez une nouvelle conversation Claude et utilisez les outils Google Workspace

### Option 2 : Installation via uvx (CLI)

```bash
# Exécution instantanée (sans installation)
uvx workspace-mcp

# Avec outils spécifiques
uvx workspace-mcp --tools gmail drive calendar

# Avec tier d'outils
uvx workspace-mcp --tool-tier core
```

### Option 3 : Installation locale

```bash
# Cloner le dépôt
git clone https://github.com/taylorwilsdon/google_workspace_mcp.git
cd google_workspace_mcp

# Installer les dépendances (avec uv)
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
uv pip install -e .

# Lancer le serveur
python main.py
```

---

## ⚙️ Configuration

### Variables d'environnement essentielles

#### Pour OAuth (comptes personnels / développement)

```bash
export GOOGLE_OAUTH_CLIENT_ID="votre-client-id.apps.googleusercontent.com"
export GOOGLE_OAUTH_CLIENT_SECRET="votre-client-secret"
```

#### Pour Service Account + DWD (production / entreprises)

```bash
# Option A : JSON complet (recommandé)
export GOOGLE_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}'

# Option B : Email + Clé privée
export GOOGLE_CLIENT_EMAIL="service-account@projet.iam.gserviceaccount.com"
export GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# Email d'impersonation (REQUIS)
export GOOGLE_IMPERSONATE_EMAIL="administrateur@domaine.com"
```

> 📖 **Documentation complète** : Voir [ENV_VARS.md](./ENV_VARS.md) et [DWD_SETUP.md](./DWD_SETUP.md) pour la configuration détaillée

### Tool Tiers

Le serveur supporte 3 niveaux d'outils :

- **`core`** : Outils essentiels pour le quotidien (42 outils)
- **`extended`** : Core + outils avancés (78 outils)
- **`complete`** : Tous les outils disponibles (117 outils)

```bash
# Utiliser un tier spécifique
uvx workspace-mcp --tool-tier core

# Ou sélectionner des outils manuellement
uvx workspace-mcp --tools gmail drive docs sheets contacts appscript
```

---

## 🏗 Architecture

### Structure du projet

```
google_workspace_mcp/
├── auth/              # Authentification (OAuth, Service Account)
├── core/              # Core du serveur MCP
├── gmail/             # Outils Gmail
├── gdrive/            # Outils Google Drive
├── gdocs/             # Outils Google Docs
├── gsheets/           # Outils Google Sheets
├── gcalendar/         # Outils Google Calendar
├── gslides/           # Outils Google Slides
├── gforms/            # Outils Google Forms
├── gchat/             # Outils Google Chat
├── gtasks/            # Outils Google Tasks
├── gcontacts/         # Outils Google Contacts (People API)
├── gappsscript/       # Outils Google Apps Script
├── gtemplates/        # Système de templates
├── gsearch/           # Custom Search
└── utils/             # Utilitaires
```

### Technologies utilisées

- **FastMCP** : Framework MCP haute performance
- **Google API Python Client** : Intégration Google Workspace APIs
- **OAuth 2.1** : Authentification moderne
- **Service Account** : Domain-Wide Delegation pour entreprises
- **Python 3.10+** : Langage de programmation

---

## 📚 Documentation

### Guides disponibles

- **[ENV_VARS.md](./ENV_VARS.md)** : Configuration complète des variables d'environnement
- **[DWD_SETUP.md](./DWD_SETUP.md)** : Guide de configuration Domain-Wide Delegation
- **[REFACTORING_SUMMARY.md](./REFACTORING_SUMMARY.md)** : Documentation technique du refactoring
- **[SECURITY.md](./SECURITY.md)** : Bonnes pratiques de sécurité

### Documentation des outils

Chaque module contient des docstrings complètes. Utilisez `help()` dans Python ou consultez le code source.

### Exemples d'utilisation

#### Recherche Gmail
```python
# Via MCP client
{
  "tool": "search_gmail_messages",
  "arguments": {
    "query": "from:example@gmail.com is:unread",
    "max_results": 10
  }
}
```

#### Création d'événement Calendar
```python
{
  "tool": "create_calendar_event",
  "arguments": {
    "summary": "Réunion équipe",
    "start": "2025-01-10T14:00:00",
    "end": "2025-01-10T15:00:00",
    "attendees": ["user@example.com"]
  }
}
```

#### Recherche Drive
```python
{
  "tool": "search_drive_files",
  "arguments": {
    "query": "name contains 'rapport' and mimeType='application/pdf'",
    "page_size": 20
  }
}
```

---

## 🔧 Développement

### Prérequis

- Python 3.10 ou supérieur
- uv (recommandé) ou pip
- Compte Google Cloud avec APIs activées

### Configuration de l'environnement de développement

```bash
# Cloner le dépôt
git clone https://github.com/taylorwilsdon/google_workspace_mcp.git
cd google_workspace_mcp

# Créer un environnement virtuel
uv venv
source .venv/bin/activate

# Installer en mode développement
uv pip install -e ".[dev]"

# Configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos identifiants
```

### Lancer les tests

```bash
# Installer les dépendances de test
uv pip install -e ".[test]"

# Lancer les tests
pytest
```

### Structure du code

- **Décorateurs** : `@require_google_service` pour l'authentification automatique
- **Gestion d'erreurs** : `@handle_http_errors` pour la gestion uniforme des erreurs
- **Tiers** : Système de tiers pour activer/désactiver des outils
- **Templates** : Système complet de templates avec variables

---

## 🔒 Sécurité

### Bonnes pratiques

1. **Ne jamais commiter** de credentials (`client_secret.json`, `.env`)
2. **Utiliser Service Account** en production plutôt que OAuth
3. **Domain-Wide Delegation** : Configurer avec les scopes minimaux nécessaires
4. **Variables d'environnement** : Utiliser des secrets management (Kubernetes Secrets, AWS Secrets Manager, etc.)
5. **HTTPS uniquement** : Ne jamais utiliser `OAUTHLIB_INSECURE_TRANSPORT=1` en production

### Scope de sécurité

Le serveur utilise le scope complet `https://www.googleapis.com/auth/drive` pour compatibilité Domain-Wide Delegation. La sécurité est gérée au niveau de l'application (prompts d'agents) et de la configuration Google Workspace.

> 📖 Voir [SECURITY.md](./SECURITY.md) pour plus de détails

---

## 🤝 Contribuer

Les contributions sont les bienvenues ! Voici comment contribuer :

1. **Fork** le projet
2. **Créer** une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. **Commit** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

### Guidelines

- Suivre les conventions de code Python (PEP 8)
- Ajouter des tests pour les nouvelles fonctionnalités
- Mettre à jour la documentation
- S'assurer que tous les tests passent

---

## 📄 Licence

Ce projet est sous licence **MIT**. Voir le fichier [LICENSE](./LICENSE) pour plus de détails.

---

## 🌟 Support

- **Issues** : [GitHub Issues](https://github.com/taylorwilsdon/google_workspace_mcp/issues)
- **Documentation** : [GitHub Wiki](https://github.com/taylorwilsdon/google_workspace_mcp/wiki)
- **Site web** : [workspacemcp.com](https://workspacemcp.com)

---

## 🙏 Remerciements

- Créé avec ❤️ par [Taylor Wilsdon](https://github.com/taylorwilsdon)
- Construit avec [FastMCP](https://github.com/jlowin/fastmcp)
- Supporte tous les comptes Google (personnels et Workspace)

---

<div align="center">

**Fait avec ❤️ pour la communauté MCP**

[⭐ Star ce projet](https://github.com/taylorwilsdon/google_workspace_mcp) • [🐛 Signaler un bug](https://github.com/taylorwilsdon/google_workspace_mcp/issues) • [💡 Proposer une fonctionnalité](https://github.com/taylorwilsdon/google_workspace_mcp/issues)

</div>
