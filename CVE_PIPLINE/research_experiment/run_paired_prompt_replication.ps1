$ErrorActionPreference='Stop'

$workspace='C:\Users\Roy\Documents\Codex\2026-08-15\cve-reproduction-pipeline'
$machineRoot=Join-Path $workspace 'work\baseline_comparison_20260827\additional-nine-persistent-grub-20260816configure\additional-nine-persistent-grub-20260816\machines'
$outRoot=Join-Path $workspace 'outputs\nlp-paired-prompt-replication-20260827'
New-Item -ItemType Directory -Path $outRoot -Force|Out-Null

$endpoint='http://127.0.0.1:11434'
$model='qwen3:14b'
$seeds=@(42,31415,271828)
$temperature=0.2
$topP=0.9
$numPredict=4096

$baselinePrompt=@'
You are a cybersecurity assistant. Read the supplied CVE description and source evidence. Identify any guest VM settings or components needed to reproduce the vulnerable environment. Return only JSON matching the requested format. If no additional settings are needed, use requirements_status "none". If the evidence is insufficient to decide, use "unknown". Include evidence for the answer.
'@.Trim()

$engineeredPrompt=@'
You analyse CVE evidence to identify EXTRA GUEST CONFIGURATION that must be applied after a separate, deterministic system has already created a VM with a vulnerable operating system and vulnerable package or kernel version. Do not choose the operating system, kernel, package version, cloud image, QEMU option, exploit or proof of concept. Do not output installation steps for the vulnerable version. Extract only prerequisites that expose or enable the affected component: loadable kernel modules, required kernel CONFIG symbols, sysctls, small enablement packages, services, exact configuration-file settings or explicit manual runtime conditions.

Return only valid JSON matching the supplied schema. Use requirements_status="identified" only when at least one prerequisite is explicitly supported by the supplied evidence. Use "none" only when the evidence explicitly supports that no extra guest configuration is required or that the affected component is reachable in the default installation. Use "unknown" when evidence is missing, conflicting or only implies a prerequisite. A subsystem name, affected source-file path, attack vector or fixed-version table does not prove that a module, CONFIG symbol, package, sysctl, service or file setting is required.

Do not classify an affected component such as af_unix, nf_tables, net/sched or a source-file name as a loaded module or service unless the evidence explicitly calls that exact name a module or service and states the required state. Do not emit mitigations or security-hardening settings: requirements and actions must expose the vulnerable component, not reduce its risk. Preserve CONFIG values exactly: y, m, n and enabled are different states. When evidence gives alternatives, retain them as a one-of group rather than making every option mandatory. A kernel CONFIG requirement is verification-only and must not become an action that rebuilds or replaces the kernel.

Every identified requirement must have a reason and an evidence item. The evidence source must exactly match a source label or URL supplied in the user message. The evidence excerpt must be a non-empty contiguous copy from that source and must contain the exact module name, CONFIG symbol, sysctl, package, service, file key or other prerequisite being claimed. Do not invent URLs, quotations, CONFIG symbols, module names or commands. If this standard cannot be met, use requirements_status="unknown" with empty requirement, action and evidence lists. Configuration actions may only represent safe typed actions supported by an identified requirement. Do not place shell commands in typed fields.
'@.Trim()

$schema=@{
 type='object';additionalProperties=$false;required=@('schema_version','requirements_status','summary','verification_requirements','configuration_actions','evidence');properties=@{
  schema_version=@{type='integer';const=2};requirements_status=@{type='string';enum=@('identified','none','unknown')};summary=@{type='string'}
  verification_requirements=@{type='object';additionalProperties=$false;required=@('kernel_modules','kernel_config','kernel_config_alternatives','sysctls','packages','services','file_settings','manual_steps');properties=@{
   kernel_modules=@{type='array';items=@{type='object';additionalProperties=$false;required=@('name','state','persistent','reason');properties=@{name=@{type='string'};state=@{type='string';const='loaded'};persistent=@{type='boolean'};reason=@{type='string'}}}}
   kernel_config=@{type='array';items=@{type='object';additionalProperties=$false;required=@('symbol','value','reason');properties=@{symbol=@{type='string';pattern='^CONFIG_[A-Z0-9_]+$'};value=@{type='string';enum=@('y','m','n','enabled')};reason=@{type='string'}}}}
   kernel_config_alternatives=@{type='array';items=@{type='object';additionalProperties=$false;required=@('one_of','reason');properties=@{one_of=@{type='array';items=@{type='object';additionalProperties=$false;required=@('symbol','value');properties=@{symbol=@{type='string';pattern='^CONFIG_[A-Z0-9_]+$'};value=@{type='string';enum=@('y','m','n','enabled')}}}};reason=@{type='string'}}}}
   sysctls=@{type='array';items=@{type='object';additionalProperties=$false;required=@('key','value','reason');properties=@{key=@{type='string'};value=@{type='string'};reason=@{type='string'}}}}
   packages=@{type='array';items=@{type='object';additionalProperties=$false;required=@('name','reason');properties=@{name=@{type='string'};reason=@{type='string'}}}}
   services=@{type='array';items=@{type='object';additionalProperties=$false;required=@('name','state','enabled','reason');properties=@{name=@{type='string'};state=@{type='string';const='active'};enabled=@{type='boolean'};reason=@{type='string'}}}}
   file_settings=@{type='array';items=@{type='object';additionalProperties=$false;required=@('path','key','value','separator','reason');properties=@{path=@{type='string'};key=@{type='string'};value=@{type='string'};separator=@{type='string';enum=@('=',' ')};reason=@{type='string'}}}}
   manual_steps=@{type='array';items=@{type='string'}}
  }}
  configuration_actions=@{type='object';additionalProperties=$false;required=@('kernel_modules','sysctls','packages','services','file_settings');properties=@{
   kernel_modules=@{type='array';items=@{type='object';additionalProperties=$false;required=@('name','state','persistent','reason');properties=@{name=@{type='string'};state=@{type='string';const='loaded'};persistent=@{type='boolean'};reason=@{type='string'}}}}
   sysctls=@{type='array';items=@{type='object';additionalProperties=$false;required=@('key','value','reason');properties=@{key=@{type='string'};value=@{type='string'};reason=@{type='string'}}}}
   packages=@{type='array';items=@{type='object';additionalProperties=$false;required=@('name','reason');properties=@{name=@{type='string'};reason=@{type='string'}}}}
   services=@{type='array';items=@{type='object';additionalProperties=$false;required=@('name','state','enabled','reason');properties=@{name=@{type='string'};state=@{type='string';const='active'};enabled=@{type='boolean'};reason=@{type='string'}}}}
   file_settings=@{type='array';items=@{type='object';additionalProperties=$false;required=@('path','key','value','separator','reason');properties=@{path=@{type='string'};key=@{type='string'};value=@{type='string'};separator=@{type='string';enum=@('=',' ')};reason=@{type='string'}}}}
  }}
  evidence=@{type='array';items=@{type='object';additionalProperties=$false;required=@('claim','source','excerpt');properties=@{claim=@{type='string'};source=@{type='string'};excerpt=@{type='string'}}}}
 }}

function Build-Evidence($bundle){
 $lines=[Collections.Generic.List[string]]::new();$lines.Add('Authoritative source evidence (use only when explicit; do not guess or merge conflicting versions):')
 foreach($r in @($bundle.reference_evidence)){$lines.Add('- Citation source (copy exactly): '+[string]$r.url);$e=[string]$r.excerpt;if($e.Length-gt1600){$e=$e.Substring(0,1600)};$lines.Add('  advisory reference excerpt: '+$e)}
 $priority=@{'Ubuntu Security Tracker'=0;'Debian Security Tracker'=1;'NVD'=2;'CVE.org / CNA record'=3;'OSV'=4}
 $ordered=@($bundle.sources)|Sort-Object @{Expression={if($priority.ContainsKey($_.name)){$priority[$_.name]}else{99}}}
 foreach($s in $ordered){$lines.Add('- Citation source (copy exactly): '+[string]$s.name);$lines.Add('  URL (also accepted as citation source): '+[string]$s.url);foreach($k in @('description','summary','details','excerpt')){$v=$s.$k;if($null-ne$v-and[string]$v-ne''){$r=if($v-is[string]){$v}else{$v|ConvertTo-Json -Compress -Depth 20};if($r.Length-gt1200){$r=$r.Substring(0,1200)};$lines.Add('  '+$k+': '+$r)}};if($s.references){$lines.Add('  reference URLs (not evidence unless excerpted below): '+((@($s.references)|Select-Object -First 6)-join', '))}}
 $joined=$lines-join"`n";if($joined.Length-gt7000){$joined=$joined.Substring(0,7000)};return $joined
}

function Sha256([string]$text){$b=[Text.Encoding]::UTF8.GetBytes($text);$s=[Security.Cryptography.SHA256]::Create();try{return([BitConverter]::ToString($s.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Signatures($o){$x=[Collections.Generic.List[string]]::new();foreach($i in @($o.verification_requirements.kernel_modules)){if($i.name){$x.Add([string]$i.name)}};foreach($i in @($o.verification_requirements.kernel_config)){if($i.symbol){$x.Add([string]$i.symbol)}};foreach($g in @($o.verification_requirements.kernel_config_alternatives)){foreach($i in @($g.one_of)){if($i.symbol){$x.Add([string]$i.symbol)}}};foreach($i in @($o.verification_requirements.sysctls)){if($i.key){$x.Add([string]$i.key)}};foreach($i in @($o.verification_requirements.packages)){if($i.name){$x.Add([string]$i.name)}};foreach($i in @($o.verification_requirements.services)){if($i.name){$x.Add([string]$i.name)}};foreach($i in @($o.verification_requirements.file_settings)){if($i.key){$x.Add([string]$i.key)}elseif($i.path){$x.Add([string]$i.path)}};foreach($i in @($o.verification_requirements.manual_steps)){if($i){$x.Add([string]$i)}};return @($x.ToArray()|Sort-Object -Unique)}
function ActionCount($o){return @($o.configuration_actions.kernel_modules).Count+@($o.configuration_actions.sysctls).Count+@($o.configuration_actions.packages).Count+@($o.configuration_actions.services).Count+@($o.configuration_actions.file_settings).Count}
function Audit([string]$cve,[string]$kind,[int]$seed,$o,[string]$user,[string]$raw,[double]$seconds,[string]$error){
 $valid=$null-ne$o;if(-not$valid){return [pscustomobject]@{cve=$cve;prompt=$kind;seed=$seed;json_valid=$false;status='invalid_json';requirements=0;actions=0;evidence_items=0;exact_evidence=0;grounded_signatures=0;unsupported_signatures=0;signatures='';response_sha256=(Sha256 $raw);duration_seconds=$seconds;error=$error}}
 $sigs=@(Signatures $o);$exact=0;foreach($e in @($o.evidence)){if($e.source-and$e.excerpt-and$user.Contains([string]$e.source)-and$user.Contains([string]$e.excerpt)){$exact++}}
 $grounded=0;foreach($sig in $sigs){$ok=$false;foreach($e in @($o.evidence)){if($e.source-and$e.excerpt-and$user.Contains([string]$e.source)-and$user.Contains([string]$e.excerpt)-and([string]$e.excerpt).Contains($sig)){$ok=$true;break}};if($ok){$grounded++}}
 return [pscustomobject]@{cve=$cve;prompt=$kind;seed=$seed;json_valid=$true;status=[string]$o.requirements_status;requirements=$sigs.Count;actions=(ActionCount $o);evidence_items=@($o.evidence).Count;exact_evidence=$exact;grounded_signatures=$grounded;unsupported_signatures=($sigs.Count-$grounded);signatures=($sigs-join'|');response_sha256=(Sha256 $raw);duration_seconds=$seconds;error=$error}
}

Set-Content -LiteralPath (Join-Path $outRoot 'baseline-system-prompt.txt') -Value $baselinePrompt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $outRoot 'engineered-system-prompt.txt') -Value $engineeredPrompt -Encoding UTF8
$schema|ConvertTo-Json -Depth 40|Set-Content -LiteralPath (Join-Path $outRoot 'output-schema.json') -Encoding UTF8
$controls=[ordered]@{experiment='paired prompt replication';date_utc=[DateTimeOffset]::UtcNow.ToString('o');endpoint=$endpoint;model=$model;seeds=$seeds;temperature=$temperature;top_p=$topP;num_predict=$numPredict;stream=$false;think=$false;evidence_limit_chars=7000;historical_reconstruction=$false;note='The engineered prompt is a frozen reconstruction for this new replication, not the missing historical rendered prompt.'}
$controls|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $outRoot 'experiment-controls.json') -Encoding UTF8
try{Invoke-RestMethod -Uri ($endpoint+'/api/version') -Method Get -TimeoutSec 30|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $outRoot 'ollama-version.json') -Encoding UTF8}catch{}
try{Invoke-RestMethod -Uri ($endpoint+'/api/tags') -Method Get -TimeoutSec 30|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $outRoot 'ollama-tags.json') -Encoding UTF8}catch{}
try{$show=@{model=$model}|ConvertTo-Json -Compress;Invoke-RestMethod -Uri ($endpoint+'/api/show') -Method Post -ContentType 'application/json' -Body $show -TimeoutSec 60|ConvertTo-Json -Depth 30|Set-Content -LiteralPath (Join-Path $outRoot 'model-show.json') -Encoding UTF8}catch{}

$cases=Get-ChildItem -LiteralPath $machineRoot -Directory|Sort-Object Name
$rows=[Collections.Generic.List[object]]::new();$orderCounter=0
foreach($seed in $seeds){foreach($case in $cases){
 $bundle=Get-Content -LiteralPath (Join-Path $case.FullName 'sources.json') -Raw|ConvertFrom-Json;$evidence=Build-Evidence $bundle;$user='Source: Primary CVE description'+"`n"+[string]$bundle.description+"`n`n"+$evidence
 $pair=if(($orderCounter%2)-eq0){@('baseline','engineered')}else{@('engineered','baseline')};$orderCounter++
 foreach($kind in $pair){
  $system=if($kind-eq'baseline'){$baselinePrompt}else{$engineeredPrompt};$dir=Join-Path $outRoot ("runs\seed-$seed\$($case.Name)\$kind");New-Item -ItemType Directory -Path $dir -Force|Out-Null
  Set-Content -LiteralPath (Join-Path $dir 'system-prompt.txt') -Value $system -Encoding UTF8;Set-Content -LiteralPath (Join-Path $dir 'user-prompt.txt') -Value $user -Encoding UTF8
  $request=[ordered]@{model=$model;system=$system;prompt=$user;stream=$false;think=$false;options=[ordered]@{num_predict=$numPredict;temperature=$temperature;top_p=$topP;seed=$seed};format=$schema}
  $body=$request|ConvertTo-Json -Depth 45 -Compress;Set-Content -LiteralPath (Join-Path $dir 'request-body.json') -Value $body -Encoding UTF8
  $envelopePath=Join-Path $dir 'response-envelope.json';$rawPath=Join-Path $dir 'raw-response.json';$raw='';$error='';$seconds=0
  if(Test-Path -LiteralPath $envelopePath){try{$env=Get-Content -LiteralPath $envelopePath -Raw|ConvertFrom-Json;$raw=[string]$env.response;$seconds=[double]$env.total_duration/1000000000}catch{}}
  if(-not$raw){Write-Output "START seed=$seed $($case.Name) $kind";$start=[DateTimeOffset]::UtcNow;try{$env=Invoke-RestMethod -Uri ($endpoint+'/api/generate') -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 900;$raw=[string]$env.response;$env|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $envelopePath -Encoding UTF8}catch{$error=$_.Exception.Message};$seconds=([DateTimeOffset]::UtcNow-$start).TotalSeconds;Write-Output "DONE seed=$seed $($case.Name) $kind $([math]::Round($seconds,1))s"}
  Set-Content -LiteralPath $rawPath -Value $raw -Encoding UTF8;$obj=$null;if($raw){try{$obj=$raw|ConvertFrom-Json}catch{$error=($_.Exception.Message)}};$rows.Add((Audit $case.Name $kind $seed $obj $user $raw ([math]::Round($seconds,3)) $error))
 }
}}

$rows|Export-Csv -LiteralPath (Join-Path $outRoot 'run-level-results.csv') -NoTypeInformation -Encoding UTF8
$aggregate=foreach($kind in @('baseline','engineered')){$r=@($rows|Where-Object {$_.prompt -eq $kind});[pscustomobject]@{prompt=$kind;runs=$r.Count;json_valid=@($r|Where-Object {$_.json_valid}).Count;identified=@($r|Where-Object {$_.status -eq 'identified'}).Count;none=@($r|Where-Object {$_.status -eq 'none'}).Count;unknown=@($r|Where-Object {$_.status -eq 'unknown'}).Count;requirements=($r|Measure-Object requirements -Sum).Sum;actions=($r|Measure-Object actions -Sum).Sum;exact_evidence=($r|Measure-Object exact_evidence -Sum).Sum;evidence_items=($r|Measure-Object evidence_items -Sum).Sum;grounded_signatures=($r|Measure-Object grounded_signatures -Sum).Sum;unsupported_signatures=($r|Measure-Object unsupported_signatures -Sum).Sum}}
$aggregate|Export-Csv -LiteralPath (Join-Path $outRoot 'aggregate-results.csv') -NoTypeInformation -Encoding UTF8
$consistency=foreach($kind in @('baseline','engineered')){foreach($case in $cases){$r=@($rows|Where-Object{$_.prompt -eq $kind -and $_.cve -eq $case.Name});$statuses=@($r.status|Sort-Object -Unique);$sigsets=@($r.signatures|Sort-Object -Unique);[pscustomobject]@{cve=$case.Name;prompt=$kind;runs=$r.Count;statuses=($statuses-join'|');status_consistent=($statuses.Count -eq 1);signature_sets=($sigsets-join' || ');signature_set_consistent=($sigsets.Count -eq 1)}}}
$consistency|Export-Csv -LiteralPath (Join-Path $outRoot 'cross-seed-consistency.csv') -NoTypeInformation -Encoding UTF8
$caseSummary=foreach($case in $cases){$b=@($rows|Where-Object{$_.prompt -eq 'baseline' -and $_.cve -eq $case.Name});$e=@($rows|Where-Object{$_.prompt -eq 'engineered' -and $_.cve -eq $case.Name});[pscustomobject]@{cve=$case.Name;baseline_statuses=($b.status-join'|');engineered_statuses=($e.status-join'|');baseline_requirements=($b.requirements-join'|');engineered_requirements=($e.requirements-join'|');baseline_grounded=($b.grounded_signatures-join'|');engineered_grounded=($e.grounded_signatures-join'|')}}
$caseSummary|Export-Csv -LiteralPath (Join-Path $outRoot 'case-comparison.csv') -NoTypeInformation -Encoding UTF8
$aggregate|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $outRoot 'aggregate-results.json') -Encoding UTF8
Write-Output 'COMPLETE';$aggregate|Format-Table -AutoSize|Out-String|Write-Output;Write-Output $outRoot
