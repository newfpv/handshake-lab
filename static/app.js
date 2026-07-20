const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const icon = name => `<svg><use href="#i-${name}"/></svg>`;
const esc = value => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const fmtBytes = value => { let n = Number(value || 0), units = ['B','KB','MB','GB']; let i = 0; while(n >= 1024 && i < 3){ n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${units[i]}`; };
const fmtDate = value => value ? new Date(value).toLocaleString([], {dateStyle:'medium', timeStyle:'short'}) : '—';
const titleCase = value => String(value || '').replaceAll('_',' ').replace(/\b\w/g, c => c.toUpperCase());
const terminalJobStates = new Set(['complete','failed','blocked','cancelled']);
const timeValue = value => { const parsed = Date.parse(value || ''); return Number.isFinite(parsed) ? parsed : null; };
const fmtDuration = value => {
  let seconds = Math.max(0, Math.round(Number(value)));
  if(!Number.isFinite(seconds)) return 'calculating';
  const days = Math.floor(seconds / 86400); seconds %= 86400;
  const hours = Math.floor(seconds / 3600); seconds %= 3600;
  const minutes = Math.floor(seconds / 60); seconds %= 60;
  if(days) return `${days}d ${hours}h`;
  if(hours) return `${hours}h ${minutes}m`;
  if(minutes) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
};

function elapsedJobSeconds(job){
  let elapsed = Math.max(0, Number(job.elapsed_seconds || 0));
  const activeStarted = timeValue(job.active_started_at);
  if(activeStarted != null && ['running','lan_preparing','lan_running'].includes(job.status)){
    elapsed += Math.max(0, (Date.now() - activeStarted) / 1000);
  }
  if(elapsed > 0 || job.started_at) return elapsed;
  return null;
}

function historicalStageSeconds(strategyId){
  const samples = state.jobs.filter(job => job.strategy_id === Number(strategyId) && job.status === 'complete').map(job => elapsedJobSeconds(job) || 0).filter(value => value > 0).sort((a,b) => a-b);
  if(!samples.length) return null;
  const middle = Math.floor(samples.length / 2);
  return samples.length % 2 ? samples[middle] : (samples[middle - 1] + samples[middle]) / 2;
}

function remainingJobSeconds(job){
  if(terminalJobStates.has(job.status)) return 0;
  const total = Number(job.candidates_total || 0), done = Number(job.candidates_done || 0), speed = Number(job.speed_hps || 0);
  if(job.status === 'running'){
    const stop = timeValue(job.eta);
    if(stop != null && stop > Date.now()) return (stop - Date.now()) / 1000;
  }
  if(total > 0 && speed > 0) return Math.max(0, total - done) / speed;
  const progress = Number(job.progress || 0), elapsed = elapsedJobSeconds(job);
  if(elapsed != null && progress > 0 && progress < 100) return elapsed * (100 - progress) / progress;
  return historicalStageSeconds(job.strategy_id);
}

function jobTimingLabel(job){
  const elapsed = elapsedJobSeconds(job);
  const remaining = remainingJobSeconds(job);
  const elapsedText = elapsed == null ? '—' : fmtDuration(elapsed);
  const remainingText = remaining == null ? 'calculating' : terminalJobStates.has(job.status) ? 'done' : `~${fmtDuration(remaining)}`;
  return `elapsed ${elapsedText} · remaining ${remainingText}`;
}

function selectedPlanEstimate(captureCount, strategyIds){
  let seconds = 0, known = 0;
  strategyIds.forEach(id => {
    const estimate = historicalStageSeconds(Number(id));
    if(estimate != null){ seconds += estimate * captureCount; known++; }
  });
  return {seconds, known, total: strategyIds.length};
}

let state = {captures:[],wordlists:[],strategies:[],presets:[],jobs:[],results:[],events:[],telemetry:[],gpu:{},tools:{},config:{}};
let settingsDirty = false;
let activePage = location.hash.slice(1) || 'dashboard';
let selectedCaptures = new Set();
let queueCaptureSelection = null;
let queueStrategySelection = null;
let refreshTimer;
let strategyDragActive = false;
let draggedStrategyId = null;
let strategyDropSide = 'before';
let jobDragActive = false;
let draggedJobId = null;
let jobDropSide = 'before';
let telemetryHoverIndex = null;
let doctorState = null;
let benchmarkTimer = null;
const accents = [
  ['cyan','#20e4f4','32,228,244'],
  ['violet','#9f7cff','159,124,255'],
  ['yellow','#ffe326','255,227,38'],
  ['green','#30e37b','48,227,123'],
  ['red','#ff4b5e','255,75,94']
];

function toast(message, error = false){
  const el = document.createElement('div');
  el.className = `toast${error ? ' error' : ''}`;
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), 4400);
}

async function api(url, options = {}){
  let response;
  try{ response = await fetch(url, options); }
  catch(error){ throw new Error('Background service is offline. Run start.bat; the release supervisor will restart future crashes automatically.'); }
  const type = response.headers.get('content-type') || '';
  const data = type.includes('json') ? await response.json() : await response.text();
  if(!response.ok) throw new Error(data.error || data.errors?.join(', ') || `Request failed (${response.status})`);
  return data;
}

function navigate(page){
  if(!document.querySelector(`[data-page="${page}"]`)) page = 'dashboard';
  activePage = page;
  history.replaceState(null, '', `#${page}`);
  $$('.page').forEach(el => el.classList.toggle('active', el.dataset.page === page));
  $$('[data-nav]').forEach(el => el.classList.toggle('active', el.dataset.nav === page));
  const labels = {dashboard:'Overview',captures:'Captures',wordlists:'Candidate sources',pipeline:'Recovery pipeline',queue:'GPU queue',results:'Recovered keys',help:'Help & Wiki',settings:'Settings'};
  $('#pageTitle').textContent = labels[page] || page;
  if(page==='settings')pollBenchmark();
  scrollTo({top:0,behavior:'smooth'});
}

async function refresh(silent = true){
  try{
    state = await api('/api/state');
    render();
  }catch(error){ if(!silent) toast(error.message, true); }
}

function render(){
  renderStats();
  renderCaptures();
  renderWordlists();
  renderPresets();
  renderStrategies();
  renderPipelineReadiness();
  renderGpu();
  renderQueue();
  renderResults();
  renderEvents();
  renderSettings();
  renderSelects();
}

function onlineLanWorkers(){
  const presenceTimeout = 15000;
  return (state.lan_workers || []).filter(worker => {
    const lastSeen = Date.parse(worker.last_seen || '');
    return worker.status !== 'offline' && Number.isFinite(lastSeen) && Date.now() - lastSeen < presenceTimeout;
  });
}

function renderStats(){
  const queued = state.jobs.filter(job => ['queued','running','paused','lan_preparing','lan_running','lan_paused'].includes(job.status));
  const connectedWorkers = onlineLanWorkers();
  const connectedNames = new Set(connectedWorkers.map(worker => worker.name));
  const running = state.jobs.find(job => ['running','paused'].includes(job.status) || (['lan_preparing','lan_running','lan_paused'].includes(job.status) && connectedNames.has(job.worker_name)));
  const networks = state.captures.reduce((sum,item) => sum + Number(item.networks || 0),0);
  const busyWorkers = connectedWorkers.filter(worker => worker.current_job_id || worker.status === 'running');
  const featuredWorker = busyWorkers[0] || connectedWorkers[0];
  $('#navCaptureCount').textContent = state.captures.length;
  $('#navQueueCount').textContent = queued.length;
  $('#navResultCount').textContent = state.results.length;
  $('#statCaptures').textContent = state.captures.length;
  $('#statNetworks').textContent = `${networks} network${networks === 1 ? '' : 's'}`;
  $('#statQueue').textContent = queued.length;
  $('#statResults').textContent = state.results.length;
  $('#statRunning').textContent = running ? `${running.capture_name} · ${running.strategy_name}` : 'No active workload';
  $('#statSpeed').textContent = running?.speed || '—';
  $('#statProgress').textContent = running ? `${Number(running.progress).toFixed(1)}% · ${running.status}` : 'Ready';
  if(running && state.gpu?.temperature != null) $('#statProgress').textContent += ` · ${Number(state.gpu.temperature).toFixed(0)}°C`;
  $('#statLanWorkers').textContent = `${connectedWorkers.length} ONLINE`;
  $('#statLanWorkerDetail').textContent = featuredWorker
    ? `${featuredWorker.name} · ${featuredWorker.current_job_id ? `Job #${featuredWorker.current_job_id}` : (connectedWorkers.includes(featuredWorker) ? 'Idle' : 'Offline')}`
    : 'No worker connected';
  const lanCard = $('#lanWorkerStat');
  lanCard.hidden = connectedWorkers.length === 0;
  lanCard.closest('.stat-grid').classList.toggle('has-lan', connectedWorkers.length > 0);
  lanCard.classList.toggle('lan-online', connectedWorkers.length > 0 && busyWorkers.length === 0);
  lanCard.classList.toggle('lan-busy', busyWorkers.length > 0);
  lanCard.classList.toggle('lan-offline', connectedWorkers.length === 0);
  lanCard.title = connectedWorkers.map(worker => `${worker.name} · ${worker.current_job_id ? `Job #${worker.current_job_id}` : 'Idle'} · ${worker.gpu_name || 'Unknown device'}`).join('\n');
  const ready = Boolean(state.tools.hashcat);
  $('#toolDot').classList.toggle('ok', ready);
  $('#toolLabel').textContent = ready ? 'Hashcat ready' : 'Engine offline';
  $('#toolHint').textContent = ready ? state.tools.hashcat : 'Configure in Settings';
  $('#engineHero').textContent = ready ? 'Hashcat is ready' : 'Waiting for Hashcat';
  $('#engineHeroPath').textContent = ready ? state.tools.hashcat : 'Configure local executable';
  $('#liveJob').className = running ? 'live-progress' : 'empty-state compact';
  $('#liveJob').innerHTML = running ? `
    <div class="live-head"><div><span class="eyebrow">JOB ${running.id}</span><h3>${esc(running.capture_name)}</h3><p>${esc(running.strategy_name)} · ${esc(running.status)}</p></div><span class="badge ${running.status === 'running' ? 'ready' : ''}">${esc(running.speed || 'Starting')}</span></div>
    <div class="progress"><i style="width:${Math.max(0,Math.min(100,running.progress))}%"></i></div>
    <div class="progress-meta"><span>${Number(running.progress).toFixed(2)}%</span><span>${esc(jobTimingLabel(running))}</span></div>` : `${icon('wave')}<b>The GPU lane is idle</b><span>Import captures and add strategies to start.</span>`;
}

function captureCard(item){
  const selected = !item.fully_recovered && selectedCaptures.has(item.id);
  const hasPassword = Boolean(item.recovered_passwords?.length);
  const diagnostic = item.diagnostic_path ? `<button class="button small diagnostics-capture">Diagnostics</button>` : '';
  const verify = item.status === 'ready' ? `<button class="button small verify-capture">Verify password</button>` : '';
  const stateLabel = item.fully_recovered ? 'Recovered' : titleCase(item.status);
  const known = hasPassword ? `<div class="capture-known">${item.recovered_passwords.map(result => `<span><small>${esc(result.essid)}</small><code>${esc(result.password)}</code></span>`).join('')}</div>` : '';
  const attempts = item.attempted_methods || [];
  const memory = attempts.length ? `<details class="capture-memory"><summary><span>TESTED METHODS</span><b>${attempts.length}</b></summary><div>${attempts.map(attempt => `<article><span><b>${esc(attempt.label)}</b><small>${attempt.networks} network${attempt.networks === 1 ? '' : 's'} · ${attempt.recovered ? `${attempt.recovered} matched` : 'no match'} · ${fmtDate(attempt.completed_at)}</small></span><em class="${attempt.recovered ? 'matched' : ''}">${attempt.recovered ? 'Recovered' : 'Exhausted'}</em></article>`).join('')}</div></details>` : '';
  const quality = item.quality || {score:0,label:'Unknown',reasons:[],recommendations:[]};
  const qualityPanel = `<details class="capture-quality"><summary><span>QUALITY ASSISTANT</span><b class="quality-${String(quality.label).toLowerCase()}">${esc(quality.label)} · ${quality.score}/100</b></summary><div class="quality-body"><p>${(quality.reasons||[]).map(esc).join(' ')}</p><ul>${(quality.recommendations||[]).map(text=>`<li>${esc(text)}</li>`).join('')}</ul><small>${quality.eapol||0} EAPOL · ${quality.pmkid||0} PMKID</small></div></details>`;
  return `<article class="capture-card${selected ? ' selected' : ''}${item.fully_recovered ? ' fully-recovered' : ''}${hasPassword ? ' has-password' : ''}" data-capture-id="${item.id}">
    <input class="select-capture" type="checkbox" ${selected ? 'checked' : ''} ${item.fully_recovered ? 'disabled' : ''} aria-label="Select ${esc(item.filename)}">
    <div class="capture-top"><div class="file-icon">${esc(item.kind.toUpperCase())}</div><button class="icon-button danger delete-capture" title="Delete">${icon('trash')}</button></div>
    <h3 title="${esc(item.filename)}">${esc(item.filename)}</h3><p>Imported ${fmtDate(item.imported_at)}</p>
    <div class="capture-details"><span><small>NETWORKS</small><b>${item.networks}</b></span><span><small>STATE</small><b>${stateLabel}</b></span></div>
    <div class="capture-note" title="${esc(item.note || 'Ready for the recovery pipeline.')}">${esc(item.note || 'Ready for the recovery pipeline.')}</div>${known}${qualityPanel}${memory}<div class="capture-actions"><span class="badge ${item.fully_recovered ? 'ready' : esc(item.status)}">${stateLabel}</span>${verify}${diagnostic}${item.status !== 'ready' ? `<button class="button small reprocess-capture">Recheck</button>` : ''}</div>
  </article>`;
}

function renderCaptures(){
  const query = ($('#captureSearch')?.value || '').toLowerCase();
  const items = state.captures.filter(item => `${item.filename} ${item.status} ${item.note} ${(item.recovered_passwords||[]).map(result=>`${result.essid} ${result.password}`).join(' ')} ${(item.attempted_methods||[]).map(attempt=>attempt.label).join(' ')}`.toLowerCase().includes(query)).sort((a,b)=>Number(Boolean(a.recovered_passwords?.length))-Number(Boolean(b.recovered_passwords?.length)));
  const recovered = items.filter(item=>item.recovered_passwords?.length).length;
  $('#captureSummary').textContent = `${items.length} item${items.length === 1 ? '' : 's'} · ${selectedCaptures.size} selected · ${recovered} with password`;
  $('#captureList').innerHTML = items.length ? items.map(captureCard).join('') : `<div class="empty-state"><svg><use href="#i-capture"/></svg><b>No captures yet</b><span>Drop a .22000, PCAP or PCAPNG file above.</span></div>`;
}

function renderWordlists(){
  const unresolved = state.captures.reduce((sum,item)=>sum+Number(item.unresolved_networks||0),0);
  const speed = Number(state.gpu?.speed_hps || Math.max(0,...state.jobs.map(job=>Number(job.speed_hps||0))));
  const analysisMarkup = item => {
    const analysis=item.analysis||{};
    if(item.kind!=='wordlist')return '';
    if(analysis.status==='processing'){
      const progress=analysis.bytes_total?Math.min(100,Number(analysis.bytes_read||0)/Number(analysis.bytes_total)*100):0;
      return `<div class="source-analysis processing"><div class="source-analysis-head"><b>ANALYZING</b><span>${progress.toFixed(1)}%</span></div><div class="progress"><i style="width:${progress}%"></i></div><small>${Number(analysis.lines||0).toLocaleString()} lines scanned</small></div>`;
    }
    if(analysis.status==='failed')return `<div class="source-analysis failed"><b>ANALYSIS FAILED</b><span>${esc(analysis.error||'Unknown error')}</span></div>`;
    if(analysis.status!=='complete')return '<div class="source-analysis empty"><span>Not analyzed yet</span></div>';
    const candidates=Number(analysis.unique_valid||0)*Math.max(1,unresolved);
    const eta=speed>0?fmtDuration(candidates/speed):'run a GPU job for ETA';
    const scope=unresolved?`${unresolved} unresolved network${unresolved===1?'':'s'}`:'per network';
    return `<div class="source-analysis"><span><b>${Number(analysis.unique_valid||0).toLocaleString()}</b><small>UNIQUE WPA</small></span><span><b>${Number(analysis.duplicates||0).toLocaleString()}</b><small>DUPLICATES</small></span><span><b>${Number(analysis.short||0).toLocaleString()}</b><small>SHORT &lt;8</small></span><span><b>${eta}</b><small>ETA · ${scope}</small></span></div>`;
  };
  $('#wordlistList').innerHTML = state.wordlists.length ? state.wordlists.map(item => `<article class="file-row">
    <div class="file-icon">${item.kind === 'rule' ? 'RULE' : 'DICT'}</div><div class="source-main"><h3>${esc(item.filename)}</h3><p>${titleCase(item.kind)} · Added ${fmtDate(item.imported_at)}</p>${analysisMarkup(item)}</div><span class="file-size">${fmtBytes(item.bytes)}</span><div class="source-actions" data-source-id="${item.id}">${item.kind === 'wordlist' ? `<button class="button small analyze-source" ${item.analysis?.status==='processing'?'disabled':''}>${item.analysis?.status==='processing'?'Analyzing…':'Analyze'}</button><button class="button small filter-short-source" title="Create a WPA-ready copy without candidates shorter than 8 bytes">Remove &lt;8</button>` : ''}<span class="source-order">#${String(item.position).padStart(2,'0')}</span><button class="icon-button source-up" title="Earlier">↑</button><button class="icon-button source-down" title="Later">↓</button></div>
  </article>`).join('') : `<div class="empty-state"><svg><use href="#i-book"/></svg><b>No candidate sources</b><span>Add your own wordlists or Hashcat rules.</span></div>`;
}

function presetStageLabels(preset){
  const labels = {known:'Potfile',common:'Common first',first_wordlists:'First sources',all_wordlists:'All dictionaries',all_rules:'Rules',mask:'Mask',strategy:'Saved stage'};
  return (preset.config?.stages || []).map(stage => `<span>${esc(labels[stage.kind] || stage.kind)}${stage.kind === 'first_wordlists' && stage.limit ? ` · ${stage.limit}` : ''}</span>`).join('');
}

function renderPresets(){
  $('#presetList').innerHTML = (state.presets || []).map(preset => `<article class="preset-card" data-preset-id="${preset.id}">
    <header><div><span class="preset-order">${preset.config.order === 'capture_first' ? 'Capture first' : 'Strategy first'} · W${preset.config.workload || 3}</span><h3>${esc(preset.name)}</h3></div><span class="badge ${preset.builtin ? 'ready' : ''}">${preset.builtin ? 'Built-in' : 'Custom'}</span></header>
    <p>${esc(preset.description)}</p><div class="preset-stages">${presetStageLabels(preset)}</div>
    <footer><button class="button primary run-preset">${icon('play')}Queue selected</button>${preset.builtin ? '' : `<button class="button delete-preset" title="Delete">${icon('trash')}</button>`}</footer>
  </article>`).join('');
}

function sourceOptions(kind, selected){
  const options = state.wordlists.filter(item => item.kind === kind);
  const empty = options.length ? `Select ${kind}` : `No ${kind} files · open Sources and scan`;
  return `<option value="">${empty}</option>${options.map(item => `<option value="${item.id}" ${Number(selected) === item.id ? 'selected' : ''}>${esc(item.filename)} · ${fmtBytes(item.bytes)}</option>`).join('')}`;
}

function configFields(stage){
  const cfg = stage.config || {};
  if(stage.mode === 'known') return `<span class="badge ready">Potfile / imported results</span>`;
  if(stage.mode === 'common') return `<span class="badge ready">Ranked common + SSID candidates</span>`;
  if(stage.mode === 'pattern') return `<span class="badge ready">Local verified-key patterns</span>`;
  if(stage.mode === 'dictionary') return `<label><small>WORDLIST</small><select data-config="wordlist_id">${sourceOptions('wordlist',cfg.wordlist_id)}</select></label>`;
  if(stage.mode === 'rules') return `<label><small>WORDLIST</small><select data-config="wordlist_id">${sourceOptions('wordlist',cfg.wordlist_id)}</select></label><label><small>RULE FILE</small><select data-config="rule_id">${sourceOptions('rule',cfg.rule_id)}</select></label>`;
  if(stage.mode === 'hybrid') return `<label><small>WORDLIST</small><select data-config="wordlist_id">${sourceOptions('wordlist',cfg.wordlist_id)}</select></label><label><small>SUFFIX MASK</small><input data-config="mask" value="${esc(cfg.mask || '?d?d?d?d')}" placeholder="Example: ?d?d?d?d"></label>`;
  if(stage.mode === 'mask') return `<label><small>HASHCAT MASK</small><input data-config="mask" value="${esc(cfg.mask || '?d?d?d?d?d?d?d?d')}" placeholder="Example: ?d?d?d?d?d?d?d?d"></label><label class="check"><input data-config="increment" type="checkbox" ${cfg.increment ? 'checked' : ''}><span><b>Increment</b><small>Try shorter lengths first</small></span></label>`;
  return '';
}

function stageIsConfigured(stage){
  const cfg = stage.config || {};
  if(stage.mode === 'known') return true;
  if(stage.mode === 'common') return true;
  if(stage.mode === 'pattern') return true;
  if(stage.mode === 'dictionary') return Boolean(cfg.wordlist_id);
  if(stage.mode === 'rules') return Boolean(cfg.wordlist_id && cfg.rule_id);
  if(stage.mode === 'hybrid') return Boolean(cfg.wordlist_id && String(cfg.mask || '').trim());
  if(stage.mode === 'mask') return Boolean(String(cfg.mask || '').trim());
  return false;
}

function renderStrategies(){
  if(strategyDragActive) return;
  const descriptions = {known:'Instant local potfile check',common:'Try likely passwords and network-name variants first',pattern:'Build ranked candidates from locally recovered password structures',dictionary:'Test one ordered source',rules:'Mutate a source with rules',hybrid:'Wordlist plus structured suffix',mask:'Structured candidate generator'};
  $('#strategyList').innerHTML = state.strategies.map((stage,index) => `<article class="strategy-card${stage.enabled ? '' : ' disabled'}${stageIsConfigured(stage) ? '' : ' needs-config'}" data-strategy-id="${stage.id}">
    <span class="stage-number">${String(index + 1).padStart(2,'0')}</span><span class="drag-handle" draggable="true" title="Drag to reorder" aria-label="Drag ${esc(stage.name)} to reorder"><svg viewBox="0 0 16 22" aria-hidden="true"><circle cx="5" cy="5" r="1.4"/><circle cx="11" cy="5" r="1.4"/><circle cx="5" cy="11" r="1.4"/><circle cx="11" cy="11" r="1.4"/><circle cx="5" cy="17" r="1.4"/><circle cx="11" cy="17" r="1.4"/></svg></span>
    <div class="strategy-main"><h3 contenteditable="true" data-name>${esc(stage.name)}</h3><span>${esc(descriptions[stage.mode] || `${titleCase(stage.mode)} attack`)}</span>${stageIsConfigured(stage) ? '' : '<em>Needs configuration</em>'}</div>
    <div class="strategy-config">${configFields(stage)}</div>
    <div class="stage-actions"><button class="toggle ${stage.enabled ? 'on' : ''}" title="Enable or disable stage" aria-pressed="${stage.enabled ? 'true' : 'false'}"><span>${stage.enabled ? 'ON' : 'OFF'}</span><i></i></button><button class="icon-button stage-up" title="Move up">↑</button><button class="icon-button stage-down" title="Move down">↓</button></div>
  </article>`).join('');
}

function renderPipelineReadiness(){
  const ready = state.captures.filter(item => item.status === 'ready').length;
  const dictionaries = state.wordlists.filter(item => item.kind === 'wordlist').length;
  const rules = state.wordlists.filter(item => item.kind === 'rule').length;
  const configured = state.strategies.filter(stage => stage.enabled && stageIsConfigured(stage)).length;
  const items = [
    [ready > 0, `${ready} ready capture${ready === 1 ? '' : 's'}`, ready ? 'Available for queueing' : 'Import or recheck a capture'],
    [dictionaries > 0, `${dictionaries} dictionar${dictionaries === 1 ? 'y' : 'ies'}`, dictionaries ? 'Ordered in Sources' : 'Link at least one wordlist'],
    [configured > 0, `${configured} configured stage${configured === 1 ? '' : 's'}`, configured ? 'Enabled and ready' : 'Configure a manual stage'],
    [true, `${rules} rule file${rules === 1 ? '' : 's'}`, rules ? 'Rules attacks available' : 'Optional'],
  ];
  $('#pipelineReadiness').innerHTML = items.map(([ok,label,hint]) => `<article class="${ok ? 'ok' : 'warn'}"><i>${ok ? '✓' : '!'}</i><span><b>${esc(label)}</b><small>${esc(hint)}</small></span></article>`).join('');
}

function sortCaptureList(captures,mode){
  const list=[...captures];
  const name=item=>String(item.primary_essid||item.filename||'').toLowerCase();
  if(mode==='likely_fastest') return list.sort((a,b)=>{
    const simple=item=>/^[a-z][a-z _-]{2,15}$/i.test(item.primary_essid||'')?0:1;
    return Number(!a.factory_ssid)-Number(!b.factory_ssid)||simple(a)-simple(b)||(a.networks||0)-(b.networks||0)||name(a).localeCompare(name(b));
  });
  if(mode==='factory_first') return list.sort((a,b)=>Number(!a.factory_ssid)-Number(!b.factory_ssid)||name(a).localeCompare(name(b)));
  if(mode==='simple_first') return list.sort((a,b)=>{
    const score=item=>/^[a-z][a-z _-]{2,15}$/i.test(item.primary_essid||'')?0:1;
    return score(a)-score(b)||name(a).localeCompare(name(b));
  });
  if(mode==='fewest_networks') return list.sort((a,b)=>(a.networks||0)-(b.networks||0)||name(a).localeCompare(name(b)));
  if(mode==='alphabetical') return list.sort((a,b)=>name(a).localeCompare(name(b)));
  if(mode==='oldest') return list.sort((a,b)=>String(a.imported_at||'').localeCompare(String(b.imported_at||'')));
  if(mode==='newest') return list.sort((a,b)=>String(b.imported_at||'').localeCompare(String(a.imported_at||'')));
  return list;
}

function renderSelects(){
  const captureSelect = $('#queueCaptures');
  const readyCaptures = sortCaptureList(state.captures.filter(item => item.status === 'ready' && !item.fully_recovered),$('#queuePriority')?.value||'likely_fastest');
  const readyCaptureIds = new Set(readyCaptures.map(item => item.id));
  selectedCaptures = new Set([...selectedCaptures].filter(id => readyCaptureIds.has(id)));
  if(queueCaptureSelection === null) queueCaptureSelection = new Set(selectedCaptures.size ? selectedCaptures : readyCaptureIds);
  else queueCaptureSelection = new Set([...queueCaptureSelection].filter(id => readyCaptureIds.has(id)));
  captureSelect.innerHTML = readyCaptures.map(item => `<option value="${item.id}" ${queueCaptureSelection.has(item.id) ? 'selected' : ''}>${item.factory_ssid?'FACTORY · ':''}${esc(item.primary_essid||item.filename)} · ${item.networks}</option>`).join('');
  const strategySelect = $('#queueStrategies');
  const enabledStrategies = state.strategies.filter(item => item.enabled);
  const enabledStrategyIds = new Set(enabledStrategies.map(item => item.id));
  if(queueStrategySelection === null) queueStrategySelection = new Set(enabledStrategyIds);
  else queueStrategySelection = new Set([...queueStrategySelection].filter(id => enabledStrategyIds.has(id)));
  strategySelect.innerHTML = enabledStrategies.map(item => `<option value="${item.id}" ${queueStrategySelection.has(item.id) ? 'selected' : ''}>${String(item.position + 1).padStart(2,'0')} · ${esc(item.name)}</option>`).join('');
  renderLaunchChoices();
}

function renderChoiceList(selectId, targetId, emptyText){
  const select = $(`#${selectId}`);
  const target = $(`#${targetId}`);
  const options = [...select.options];
  target.innerHTML = options.length ? options.map(option => `<button type="button" class="queue-choice${option.selected ? ' selected' : ''}" data-select-id="${selectId}" data-value="${option.value}" aria-pressed="${option.selected ? 'true' : 'false'}"><i></i><span>${esc(option.textContent)}</span></button>`).join('') : `<span class="choice-empty">${esc(emptyText)}</span>`;
}

function updateLaunchSummary(){
  const captures = selectedQueueCaptures().length;
  const strategyIds = [...$('#queueStrategies').selectedOptions].map(option => Number(option.value));
  const stages = strategyIds.length;
  const order = $('#queueOrder').value;
  const priority = $('#queuePriority').selectedOptions[0]?.textContent || 'Current order';
  const jobs = captures * stages;
  $('#queueOrderHelp').textContent = order === 'capture_first' ? 'Finish all selected stages on one capture, then move to the next.' : 'Run the first stage on every capture, then advance to the next stage.';
  const estimate = selectedPlanEstimate(captures, strategyIds);
  const estimateText = estimate.known ? ` · approximately ${fmtDuration(estimate.seconds)} from history${estimate.known < estimate.total ? ` (${estimate.known}/${estimate.total} stages estimated)` : ''}` : '';
  $('#launchSummary').innerHTML = jobs ? `<b>${jobs} separate GPU job${jobs === 1 ? '' : 's'}</b><span>${captures} capture${captures === 1 ? '' : 's'} × ${stages} stage${stages === 1 ? '' : 's'} · ${order === 'capture_first' ? 'capture first' : 'strategy first'} · ${esc(priority)}${esc(estimateText)}</span>` : `<b>Nothing will start yet</b><span>Choose at least one Ready capture and one enabled stage.</span>`;
  $('#startQueueCount').textContent = `${jobs} job${jobs === 1 ? '' : 's'}`;
  $('#startQueue').disabled = !jobs;
}

function renderLaunchChoices(){
  renderChoiceList('queueCaptures','queueCaptureChoices','No Ready captures');
  renderChoiceList('queueStrategies','queueStrategyChoices','No enabled stages');
  updateLaunchSummary();
}

function jobButtons(job){
  if(job.status === 'running') return `<button class="icon-button job-action" data-action="pause" title="Pause">${icon('pause')}</button><button class="icon-button job-action danger" data-action="cancel" title="Cancel">×</button>`;
  if(job.status === 'paused') return `<button class="icon-button job-action" data-action="resume" title="Resume">${icon('play')}</button><button class="icon-button job-action danger" data-action="cancel" title="Cancel">×</button>`;
  if(job.status === 'lan_running') return `<button class="icon-button job-action" data-action="pause" title="Pause">${icon('pause')}</button><button class="icon-button job-action danger" data-action="cancel" title="Cancel">×</button>`;
  if(job.status === 'lan_paused') return `<button class="icon-button job-action" data-action="resume" title="Resume">${icon('play')}</button><button class="icon-button job-action danger" data-action="cancel" title="Cancel">×</button>`;
  if(['blocked','failed','cancelled'].includes(job.status)) return `<button class="button small job-action" data-action="retry">Retry</button>`;
  return '';
}

function renderQueue(){
  if(jobDragActive) return;
  const pending = state.jobs.filter(job => ['queued','running','paused','lan_preparing','lan_running','lan_paused'].includes(job.status));
  let estimatedSeconds = 0, unknownEstimates = 0;
  pending.forEach(job => { const estimate = remainingJobSeconds(job); if(estimate == null) unknownEstimates++; else estimatedSeconds += estimate; });
  const estimatePrefix = unknownEstimates ? 'At least' : 'Approximately';
  $('#queueEstimate').textContent = pending.length ? `${estimatePrefix} ${fmtDuration(estimatedSeconds)} remaining · ${pending.length} active/waiting${unknownEstimates ? ` · ${unknownEstimates} still calculating` : ''}` : 'Queue complete · no waiting jobs';
  const connectedNames = new Set(onlineLanWorkers().map(worker => worker.name));
  $('#queueList').innerHTML = state.jobs.length ? state.jobs.map(job => {
    const remoteOffline = job.status.startsWith('lan_') && !connectedNames.has(job.worker_name);
    const visibleStatus = remoteOffline ? (job.status === 'lan_paused' ? 'paused' : 'waiting') : job.status.replace(/^lan_/, '');
    const visibleError = String(job.error || '').replace(/^LAN worker /, 'Worker ');
    const elapsed = elapsedJobSeconds(job), remaining = remainingJobSeconds(job);
    const elapsedText = elapsed == null ? '—' : fmtDuration(elapsed);
    const remainingText = remaining == null ? 'Calculating' : terminalJobStates.has(job.status) ? 'Done' : `~${fmtDuration(remaining)}`;
    const candidatesText = job.candidates_total ? `${Number(job.candidates_done).toLocaleString()} / ${Number(job.candidates_total).toLocaleString()}` : 'Waiting for keyspace';
    return `<article class="job-row ${job.status}" data-job-id="${job.id}">
    <span class="job-id">#${String(job.id).padStart(3,'0')}</span><div class="job-main"><h3>${esc(job.capture_name)}</h3><p>${job.preset_name ? `${esc(job.preset_name)} · ` : ''}${esc(job.strategy_name)}${visibleError ? ` · ${esc(visibleError)}` : ''}</p></div>
    <span class="job-status">${esc(visibleStatus)} · W${job.workload || 3}</span><div class="job-progress"><div class="progress"><i style="width:${Math.max(0,Math.min(100,job.progress))}%"></i></div><div class="job-progress-metrics"><span><small>PROGRESS</small><b>${Number(job.progress).toFixed(2)}%</b></span><span><small>SPEED</small><b>${esc(job.speed || '—')}</b></span></div><div class="job-time-metrics"><span><small>CANDIDATES</small><b>${candidatesText}</b></span><span><small>ELAPSED</small><b>${elapsedText}</b></span><span><small>REMAINING</small><b>${remainingText}</b></span></div></div><div class="job-actions">${jobButtons(job)}</div>
  </article>`}).join('') : `<div class="empty-state"><svg><use href="#i-wave"/></svg><b>The queue is empty</b><span>Configure a pipeline and choose Start queue.</span></div>`;
  $$('.job-row').forEach(row => {
    const label = $('.job-id', row);
    const order = document.createElement('div');
    order.className = 'job-order';
    label.before(order);
    if(row.classList.contains('queued')) order.insertAdjacentHTML('beforeend','<span class="job-drag-handle" draggable="true" title="Drag waiting job"><svg viewBox="0 0 16 22" aria-hidden="true"><circle cx="5" cy="5" r="1.4"/><circle cx="11" cy="5" r="1.4"/><circle cx="5" cy="11" r="1.4"/><circle cx="11" cy="11" r="1.4"/><circle cx="5" cy="17" r="1.4"/><circle cx="11" cy="17" r="1.4"/></svg></span>');
    order.append(label);
    const actions = $('.job-actions', row);
    const job = state.jobs.find(item => item.id === Number(row.dataset.jobId));
    if(job?.passwords?.length){
      const details = row.children[1];
      details.insertAdjacentHTML('beforeend',`<div class="job-passwords">${job.passwords.map(item => `<span><small>${esc(item.essid)}</small><code>${esc(item.password)}</code><button class="copy-result" data-password="${esc(item.password)}" title="Copy password">${icon('copy')}</button></span>`).join('')}</div>`);
    }
    if(job?.log_path) actions.insertAdjacentHTML('afterbegin',`<button class="icon-button job-log" title="Open process log">${icon('help')}</button>`);
    if(job && !['running','paused','lan_preparing','lan_running','lan_paused'].includes(job.status)) actions.insertAdjacentHTML('beforeend',`<button class="icon-button danger delete-job" title="Delete job">${icon('trash')}</button>`);
  });
}

function metric(value,suffix='',digits=0){ return value == null || Number.isNaN(Number(value)) ? '—' : `${Number(value).toFixed(digits)}${suffix}`; }

function renderGpu(){
  const gpu = state.gpu || {};
  const activeJob=state.jobs.find(job=>['running','paused'].includes(job.status));
  const globallyPaused=Boolean(state.config.queue_paused);
  const locallyPaused=Boolean(state.config.local_queue_paused);
  const workers=onlineLanWorkers();
  const hasLanWorkers=workers.length>0;
  $('#queueSubtitle').textContent=hasLanWorkers?'Each connected computer has independent telemetry, power profiles and pause controls. Pause all remains the master switch.':'Persistent local telemetry, power profile and pause controls. Close the browser whenever you want; the queue keeps running.';
  $('#localGpuLabel').innerHTML=`<i></i> ${hasLanWorkers?'COORDINATOR':'LOCAL GPU'} · LIVE NVIDIA TELEMETRY`;
  $('#gpuSpeed').textContent = gpu.speed_hps ? humanRate(gpu.speed_hps) : '—';
  $('#gpuTemp').textContent = metric(gpu.temperature,'°C');
  $('#gpuLoad').textContent = metric(gpu.utilization,'%');
  $('#cpuLoad').textContent = metric(state.cpu?.load,'%');
  $('#gpuMemory').textContent = gpu.memory_used == null ? '—' : `${(gpu.memory_used/1024).toFixed(1)} / ${(gpu.memory_total/1024).toFixed(1)} GB`;
  $('#gpuPower').textContent = gpu.power_draw == null ? '—' : `${metric(gpu.power_draw,' W',0)} / ${metric(gpu.power_limit,' W',0)}`;
  $('#gpuClock').textContent = gpu.clock_graphics == null ? '—' : `${metric(gpu.clock_graphics,' MHz')} · ${metric(gpu.fan_speed,'%')}`;
  $('#gpuTelemetryTime').textContent = gpu.sampled_at ? `${gpu.job_id ? `Job #${gpu.job_id}` : 'GPU idle'} · ${fmtDate(gpu.sampled_at)}` : 'Waiting for telemetry';
  $('#chartLoadValue').textContent=metric(gpu.utilization,'%');
  $('#chartTempValue').textContent=metric(gpu.temperature,'°C');
  $('#chartLimitValue').textContent=`${state.config.temperature_abort||90}°C`;
  if(document.activeElement!==$('#liveWorkload'))$('#liveWorkload').value=String(activeJob?.workload||state.config.workload_profile||3);
  const cpuSelect=$('#liveCpuProfile');
  if(document.activeElement!==cpuSelect)cpuSelect.value=state.config.cpu_profile||'off';
  const cpuAvailable=Boolean(state.tools.cpu_available);
  cpuSelect.title=cpuAvailable?`${state.tools.cpu_name} · profile applies to waiting jobs`:(hasLanWorkers?`${state.tools.cpu_name} on this coordinator · connected workers may still use their own CPU backend`:`${state.tools.cpu_name} · no compatible local CPU backend detected`);
  const master=$('#pauseAllJobs');master.classList.toggle('primary',globallyPaused);master.innerHTML=globallyPaused?`${icon('play')}<span>Resume all</span>`:`${icon('pause')}<span>Pause all</span>`;master.title=globallyPaused?'Resume the entire persistent queue':'Pause the active job and hold the queue';
  const localPause=$('#pauseLocalGpu');localPause.classList.toggle('primary',locallyPaused);localPause.innerHTML=locallyPaused?`${icon('play')}<span>Resume RTX 3060</span>`:`${icon('pause')}<span>Pause RTX 3060</span>`;
  const lanConsoles=$('#lanGpuConsoles');
  lanConsoles.hidden=!hasLanWorkers;
  lanConsoles.innerHTML=workers.map(worker=>{
    const telemetry=worker.telemetry||{},online=true;
    const job=state.jobs.find(item=>item.id===worker.current_job_id),paused=Boolean(worker.paused),gpuName=telemetry.device_name||worker.gpu_name||'LAN GPU';
    const memory=telemetry.memory_used==null?'—':`${(Number(telemetry.memory_used)/1024).toFixed(1)} / ${(Number(telemetry.memory_total)/1024).toFixed(1)} GB`;
    const power=telemetry.power_draw==null?'—':`${metric(telemetry.power_draw,' W',0)}${telemetry.power_limit!=null?` / ${metric(telemetry.power_limit,' W',0)}`:''}`;
    const clock=telemetry.clock_graphics==null?'—':`${metric(telemetry.clock_graphics,' MHz')} · ${metric(telemetry.fan_speed,'%')}`;
    const workerVersion=telemetry.capabilities?.worker_version;
    const telemetryNote=telemetry.source==='last_job'?`Last Job #${telemetry.job_id} sample · restart the worker for live telemetry`:(!workerVersion?'Worker update required · replace the portable files and restart start-worker.bat':(telemetry.sampled_at?`Live telemetry · worker v${workerVersion} · ${fmtDate(telemetry.sampled_at)}`:`Worker v${workerVersion} connected · waiting for telemetry`));
    return `<section class="gpu-console remote-gpu-console ${online?'online':'offline'}" data-worker="${esc(worker.name)}"><div class="gpu-console-head"><div><span class="eyebrow"><i></i> LAN WORKER · ${esc(worker.name)} · ${online?'ONLINE':'OFFLINE'}</span><h2>${esc(gpuName)}</h2><span>${job?`Job #${job.id} · ${esc(job.status)}`:(online?'Waiting for a job':'Last seen '+fmtDate(worker.last_seen))}</span></div><div class="gpu-lane-controls"><label class="queue-profile"><span>CPU</span><select class="remote-cpu-profile"><option value="off">Off</option><option value="low" ${worker.cpu_profile==='low'?'selected':''}>Low · 25%</option><option value="balanced" ${worker.cpu_profile==='balanced'?'selected':''}>Balanced · 50%</option><option value="high" ${worker.cpu_profile==='high'?'selected':''}>High · all cores</option></select></label><label class="queue-profile"><span>GPU</span><select class="remote-workload"><option value="1" ${Number(worker.workload)===1?'selected':''}>W1 · Low</option><option value="2" ${Number(worker.workload)===2?'selected':''}>W2 · Gaming</option><option value="3" ${Number(worker.workload||3)===3?'selected':''}>W3 · High</option><option value="4" ${Number(worker.workload)===4?'selected':''}>W4 · Maximum</option></select></label><button class="button lane-pause remote-pause ${paused?'primary':''}">${paused?icon('play'):icon('pause')}<span>${paused?'Resume':'Pause'} ${esc(worker.name)}</span></button></div></div><div class="gpu-metrics remote-metrics"><article><span>SPEED</span><b>${telemetry.speed_hps?humanRate(telemetry.speed_hps):(job?.speed||'—')}</b></article><article><span>TEMP</span><b>${metric(telemetry.temperature,'°C')}</b></article><article><span>GPU LOAD</span><b>${metric(telemetry.utilization,'%')}</b></article><article><span>VRAM</span><b>${memory}</b></article><article><span>POWER</span><b>${power}</b></article><article><span>CLOCK / FAN</span><b>${clock}</b></article></div><div class="remote-lane-state"><i style="--load:${Math.max(0,Math.min(100,Number(telemetry.utilization||0)))}%"></i><span>${online?(worker.current_job_id?`Active on Job #${worker.current_job_id}`:'Connected · idle'):'Worker is offline'}</span><small>${esc(telemetryNote)}</small></div></section>`;
  }).join('');
  drawTelemetry();
}

function humanRate(value){ let n=Number(value||0),u=['H/s','kH/s','MH/s','GH/s','TH/s'],i=0; while(n>=1000&&i<u.length-1){n/=1000;i++} return `${n.toFixed(1)} ${u[i]}`; }

function drawTelemetry(){
  const canvas=$('#telemetryChart'); if(!canvas) return;
  const box=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;
  canvas.width=Math.max(1,Math.round(box.width*dpr)); canvas.height=Math.max(1,Math.round(box.height*dpr));
  const ctx=canvas.getContext('2d'); ctx.scale(dpr,dpr); const w=box.width,h=box.height;
  const plot={left:44,right:54,top:38,bottom:24};
  const pw=Math.max(1,w-plot.left-plot.right),ph=Math.max(1,h-plot.top-plot.bottom);
  ctx.clearRect(0,0,w,h);ctx.font='9px ui-monospace,Consolas,monospace';ctx.textBaseline='middle';
  [100,75,50,25,0].forEach(value=>{const y=plot.top+(100-value)/100*ph;ctx.beginPath();ctx.moveTo(plot.left,y);ctx.lineTo(w-plot.right,y);ctx.strokeStyle='rgba(255,255,255,.065)';ctx.lineWidth=1;ctx.stroke();ctx.textAlign='right';ctx.fillStyle='#718087';ctx.fillText(`${value}%`,plot.left-7,y)});
  [100,80,60,40,20].forEach(value=>{const y=plot.top+(100-value)/80*ph;ctx.textAlign='left';ctx.fillStyle='#d66a73';ctx.fillText(`${value}°`,w-plot.right+7,y)});
  ctx.save();ctx.translate(10,plot.top+ph/2);ctx.rotate(-Math.PI/2);ctx.textAlign='center';ctx.fillStyle='#718087';ctx.font='bold 8px ui-monospace,Consolas,monospace';ctx.fillText('GPU LOAD',0,0);ctx.restore();
  ctx.save();ctx.translate(w-9,plot.top+ph/2);ctx.rotate(Math.PI/2);ctx.textAlign='center';ctx.fillStyle='#d66a73';ctx.font='bold 8px ui-monospace,Consolas,monospace';ctx.fillText('TEMPERATURE °C',0,0);ctx.restore();
  const limit=Math.max(20,Math.min(100,Number(state.config.temperature_abort||90))),limitY=plot.top+(100-limit)/80*ph;ctx.setLineDash([5,5]);ctx.beginPath();ctx.moveTo(plot.left,limitY);ctx.lineTo(w-plot.right,limitY);ctx.strokeStyle='rgba(255,91,104,.42)';ctx.stroke();ctx.setLineDash([]);ctx.fillStyle='#ff7b85';ctx.textAlign='right';ctx.font='bold 8px ui-monospace,Consolas,monospace';ctx.fillText(`LIMIT ${limit}°C`,w-plot.right-5,limitY-7);
  const samples=(state.telemetry||[]).slice(-120),tooltip=$('#telemetryTooltip');if(!samples.length){tooltip.hidden=true;return}
  const point=(sample,index,key,min,max)=>{const value=Math.max(min,Math.min(max,Number(sample[key]||0)));return{x:plot.left+(samples.length===1?pw:index/(samples.length-1)*pw),y:plot.top+(max-value)/(max-min)*ph,value}};
  const line=(key,color,min,max)=>{ctx.beginPath();samples.forEach((sample,index)=>{const p=point(sample,index,key,min,max);index?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y)});ctx.strokeStyle=color;ctx.lineWidth=2.4;ctx.lineJoin='round';ctx.stroke();const last=point(samples.at(-1),samples.length-1,key,min,max);ctx.beginPath();ctx.arc(last.x,last.y,3.5,0,Math.PI*2);ctx.fillStyle=color;ctx.fill()};
  const accent=getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();line('utilization',accent,0,100);line('temperature','#ff5b68',20,100);
  if(telemetryHoverIndex!=null){const index=Math.max(0,Math.min(samples.length-1,telemetryHoverIndex)),sample=samples[index],load=point(sample,index,'utilization',0,100),temp=point(sample,index,'temperature',20,100);ctx.beginPath();ctx.moveTo(load.x,plot.top);ctx.lineTo(load.x,plot.top+ph);ctx.strokeStyle='rgba(255,255,255,.35)';ctx.lineWidth=1;ctx.stroke();[[load,accent],[temp,'#ff5b68']].forEach(([p,color])=>{ctx.beginPath();ctx.arc(p.x,p.y,4.5,0,Math.PI*2);ctx.fillStyle='#080b0c';ctx.fill();ctx.strokeStyle=color;ctx.lineWidth=2;ctx.stroke()});tooltip.hidden=false;tooltip.style.left=`${Math.max(8,Math.min(w-198,load.x+12))}px`;tooltip.style.top=`${plot.top+8}px`;tooltip.innerHTML=`<time>${fmtDate(sample.created_at)}</time><b class="temp">${metric(sample.temperature,'°C')}</b><span>GPU load <strong>${metric(sample.utilization,'%')}</strong></span><span>Speed <strong>${sample.speed_hps?humanRate(sample.speed_hps):'—'}</strong></span>`}else tooltip.hidden=true;
}

function setCascadeBusy(busy){
  const button=$('#cascadeDedupButton'),run=$('#runCascadeDedup'),dialog=$('#cascadeDedupDialog');
  button.disabled=busy;button.classList.toggle('processing',busy);button.innerHTML=busy?'<i class="spinner"></i><span>Processing...</span>':`${icon('layers')}<span>Cascade deduplication</span>`;
  run.disabled=busy;run.classList.toggle('processing',busy);run.innerHTML=busy?'<i class="spinner"></i><span>Processing...</span>':`${icon('layers')}<span>Proceed</span>`;
  $$('#cancelCascadeDedup,header button',dialog).forEach(item=>item.disabled=busy);
}

function openCascadeDedup(){
  const dictionaries=state.wordlists.filter(item=>item.kind!=='rule'&&!item.filename.toLowerCase().endsWith('.rule'));
  if(!dictionaries.length){toast('Add at least one dictionary first',true);return}
  $('#dedupOrder').innerHTML=dictionaries.map((item,index)=>`<span><b>${String(index+1).padStart(2,'0')}</b><code>${esc(item.filename)}</code><small>${fmtBytes(item.bytes)}</small></span>`).join('');
  $('#cascadeResult').hidden=true;$('#cascadeResult').className='verify-result';$('#cascadeResult').innerHTML='';
  $('#cascadeDedupDialog').showModal();
}

async function runCascadeDedup(event){
  event.preventDefault();
  const paths=state.wordlists.map(item=>item.stored_path);
  if(!paths.length)return;
  setCascadeBusy(true);
  const resultBox=$('#cascadeResult');resultBox.hidden=false;resultBox.className='verify-result working';resultBox.innerHTML='<b>Processing dictionaries in order</b><span>Keep this app running. Large sources may take several minutes.</span>';
  try{
    const result=await api('/api/wordlists/cascade-deduplicate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths})});
    resultBox.className='verify-result valid';resultBox.innerHTML=`<b>Optimization complete</b><span>${result.processed_files} file${result.processed_files===1?'':'s'} · ${result.input_lines.toLocaleString()} read · ${result.removed_lines.toLocaleString()} duplicates removed · ${result.written_lines.toLocaleString()} retained</span>`;
    await refresh();toast(`Removed ${result.removed_lines.toLocaleString()} duplicate candidate${result.removed_lines===1?'':'s'}`);
  }catch(error){resultBox.className='verify-result invalid';resultBox.innerHTML=`<b>Optimization failed</b><span>${esc(error.message)}</span>`;toast(error.message,true)}finally{setCascadeBusy(false)}
}

function renderResults(){
  const query = ($('#resultSearch')?.value || '').toLowerCase();
  const rows = state.results.filter(item => `${item.essid} ${item.bssid} ${item.strategy}`.toLowerCase().includes(query));
  $('#resultCountLabel').textContent = `${rows.length} verified`;
  $('#resultRows').innerHTML = rows.length ? rows.map(item => `<tr><td class="network-cell"><b>${esc(item.essid)}</b><small>Capture ${item.capture_id || '—'}</small></td><td><code>${esc(item.bssid || '—')}</code></td><td class="password-cell"><code>${esc(item.password)}</code></td><td><span class="badge ready">${esc(item.strategy)}</span></td><td>${fmtDate(item.found_at)}</td><td><button class="icon-button copy-result" data-password="${esc(item.password)}" title="Copy">${icon('copy')}</button></td></tr>`).join('') : `<tr><td colspan="6"><div class="empty-state compact"><svg><use href="#i-key"/></svg><b>No recovered keys</b><span>Verified results will be written here and to CSV.</span></div></td></tr>`;
}

function renderEvents(){
  $('#events').innerHTML = state.events.length ? state.events.map(item => `<div class="event ${esc(item.level)}"><i></i><span><b>${esc(item.message)}</b><time>${fmtDate(item.created_at)}</time></span></div>`).join('') : `<div class="empty-state compact"><b>No events yet</b><span>Import a capture to begin.</span></div>`;
}

function renderSettings(){
  if(!settingsDirty){
    $('#hashcatPath').value = state.config.hashcat_path || '';
    $('#hcxPath').value = state.config.hcxpcapngtool_path || '';
    $('#hostSetting').value = state.config.host || '127.0.0.1';
    $('#portSetting').value = state.config.port || 8787;
    $('#workerSetting').value = state.config.max_workers || 1;
    $('#workloadSetting').value = state.config.workload_profile || 3;
    $('#temperatureSetting').value = state.config.temperature_abort || 90;
    $('#lanEnabled').checked = Boolean(state.config.lan_enabled);
    $('#lanToken').value = state.config.lan_token || '';
    $('#lanTimeout').value = state.config.lan_job_timeout || 180;
    $('#windowsNotifications').checked = Boolean(state.config.notifications_windows);
    $('#telegramNotifications').checked = Boolean(state.config.notifications_telegram);
    $('#telegramBotToken').value = state.config.telegram_bot_token || '';
    $('#telegramChatId').value = state.config.telegram_chat_id || '';
    $('#telegramFileIntake').checked = Boolean(state.config.telegram_file_intake);
    $('#notifyPassword').checked = state.config.notify_password_found !== false;
    $('#notifyOverheat').checked = state.config.notify_overheat !== false;
    $('#notifyWorker').checked = state.config.notify_worker_error !== false;
    $('#notifyQueue').checked = state.config.notify_queue_complete !== false;
    $('#telegramBotToken').disabled=!$('#telegramNotifications').checked;
    $('#telegramChatId').disabled=!$('#telegramNotifications').checked;
    $('#telegramFileIntake').disabled=!$('#telegramNotifications').checked;
    $('#remoteAccessEnabled').checked=Boolean(state.config.remote_access_enabled);
    $('#remoteUsername').value=state.config.remote_username||'newfpv';
    $('#remoteHttpsUrl').value=state.config.remote_https_url||'';
    $('#selfSignedHttps').checked=Boolean(state.config.self_signed_https_enabled);
    $('#httpsPort').value=state.config.https_port||8788;
    $('#remotePassword').placeholder=state.config.remote_password_configured?'Configured · enter only to replace':'At least 12 characters';
  }
  const workers=onlineLanWorkers();
  const workerList=$('#lanWorkerList');
  workerList.hidden=!workers.length;
  workerList.innerHTML=workers.map(worker=>{const caps=worker.telemetry?.capabilities||{};return `<article><i class="${esc(worker.status)}"></i><span><b>${esc(worker.name)}</b><small>${esc(worker.gpu_name||'GPU worker')} · ${caps.cpu_available?'CPU ready':'GPU only'} · ${esc(worker.status)} · ${fmtDate(worker.last_seen)}</small></span><em>${worker.current_job_id?`Job #${worker.current_job_id}`:'Idle'}</em></article>`}).join('');
}

function markSettingsDirty(){
  settingsDirty=true;
  const button=$('#saveSettings');
  button.classList.add('settings-dirty');
  button.innerHTML=`${icon('check')}Save changes`;
}

function renderBenchmark(result){
  const box=$('#benchmarkStatus');
  box.className=`benchmark-status ${result.status||'idle'}`;
  if(result.status==='running')box.innerHTML='<b>Benchmark running…</b><span>Exclusive WPA 22000 W4 measurement in progress.</span>';
  else if(result.status==='complete')box.innerHTML=`<b>${esc(result.speed)}</b><span>Measured locally · ${esc(fmtDate(result.finished_at))}</span>`;
  else if(result.status==='failed')box.innerHTML=`<b>Benchmark failed</b><span>${esc(result.error)}</span>`;
  else box.innerHTML='<b>WPA 22000 benchmark</b><span>Requires an idle GPU and takes about 20 seconds.</span>';
}

async function pollBenchmark(){
  clearTimeout(benchmarkTimer);
  try{const result=await api('/api/benchmark');renderBenchmark(result);if(result.status==='running')benchmarkTimer=setTimeout(pollBenchmark,1000)}catch(error){toast(error.message,true)}
}

function renderDoctor(report){
  doctorState=report;
  const card=$('#doctorCard');card.hidden=false;
  $('#doctorFixAll').hidden=!report.fixable;
  $('#doctorResults').innerHTML=report.issues.map(issue=>`<article class="doctor-issue ${esc(issue.severity)}"><i></i><span><b>${esc(issue.title)}</b><small>${esc(issue.detail)}</small></span>${issue.fixable?`<button class="button small doctor-fix" data-action="${esc(issue.action)}">${esc(issue.fix_label||'Fix')}</button>`:''}</article>`).join('');
}

async function runDoctor(button=$('#runDoctor')){
  const original=button.innerHTML;button.disabled=true;button.innerHTML='<i class="spinner"></i><span>Checking…</span>';
  try{const report=await api('/api/doctor');renderDoctor(report);$('#doctorCard').scrollIntoView({behavior:'smooth',block:'start'});toast(report.fixable?`${report.fixable} safe fix${report.fixable===1?'':'es'} available`:'Error Doctor found no automatic fixes')}catch(error){toast(error.message,true)}finally{button.disabled=false;button.innerHTML=original}
}

async function applyDoctor(action,button){
  const original=button.textContent;button.disabled=true;button.textContent='Fixing…';
  try{const result=await api('/api/doctor/fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});renderDoctor(result.report);await refresh();toast(result.changes.join(' · '))}catch(error){toast(error.message,true)}finally{button.disabled=false;button.textContent=original}
}

async function uploadFiles(url, files){
  if(!files?.length) return;
  const oversized = url === '/api/wordlists' ? [...files].filter(file => file.size > 512 * 1024 * 1024) : [];
  if(oversized.length){
    toast('Large sources must be linked locally. Copy them into M:\\Handshakes\\wordlists, then press Scan local folder.', true);
    try{
      const result = await api('/api/wordlists/scan', {method:'POST'});
      if(result.imported.length){ toast(`Linked ${result.imported.length} local source${result.imported.length === 1 ? '' : 's'} instantly`); await refresh(); }
    }catch(error){ toast(error.message, true); }
    return;
  }
  const form = new FormData();
  [...files].forEach(file => form.append('files', file));
  toast(`Uploading ${files.length} file${files.length === 1 ? '' : 's'}…`);
  try{
    const result = await api(url, {method:'POST', body:form});
    const newNetworks = url === '/api/captures' ? result.imported.reduce((sum,item)=>sum+Number(item.networks||0),0) : 0;
    const skippedNetworks = url === '/api/captures' ? result.imported.reduce((sum,item)=>sum+Number(item.skipped_networks||0),0) : 0;
    toast(`Imported ${result.imported.length} file${result.imported.length === 1 ? '' : 's'}${url === '/api/captures' ? ` · ${newNetworks} new network${newNetworks === 1 ? '' : 's'}${skippedNetworks ? ` · ${skippedNetworks} duplicate record${skippedNetworks === 1 ? '' : 's'} skipped` : ''}` : ''}${result.errors.length ? ` · ${result.errors.length} file${result.errors.length === 1 ? '' : 's'} skipped` : ''}`);
    await refresh();
  }catch(error){ toast(error.message, true); }
}

async function updateStrategy(card){
  const id = Number(card.dataset.strategyId);
  const stage = state.strategies.find(item => item.id === id);
  const config = {...stage.config};
  $$('[data-config]',card).forEach(input => config[input.dataset.config] = input.type === 'checkbox' ? input.checked : (input.dataset.config.endsWith('_id') ? (Number(input.value) || null) : input.value));
  const payload = {name:$('[data-name]',card).textContent.trim(),config,enabled:$('.toggle',card).classList.contains('on'),position:stage.position};
  await api(`/api/strategies/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
}

async function saveStrategyOrder(ordered){
  state.strategies = ordered.map((item, position) => ({...item, position}));
  renderStrategies();
  renderSelects();
  await api('/api/strategies/order',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({strategy_ids:ordered.map(item => item.id)})});
  await refresh();
}

async function reorderStrategy(id, direction){
  const ordered = [...state.strategies];
  const index = ordered.findIndex(item => item.id === id);
  const next = index + direction;
  if(index < 0 || next < 0 || next >= ordered.length) return;
  [ordered[index],ordered[next]] = [ordered[next],ordered[index]];
  await saveStrategyOrder(ordered);
}

async function reorderSource(id,direction){
  const source=state.wordlists.find(item=>item.id===id); if(!source)return;
  const ordered=state.wordlists.filter(item=>item.kind===source.kind);
  const index=ordered.findIndex(item=>item.id===id),next=index+direction;
  if(index<0||next<0||next>=ordered.length)return;
  [ordered[index],ordered[next]]=[ordered[next],ordered[index]];
  await Promise.all(ordered.map((item,position)=>api(`/api/wordlists/${item.id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({position:position+1})})));
  await refresh();
}

async function saveJobOrder(jobIds){
  const positions = new Map(jobIds.map((id,index) => [id,index + 1]));
  state.jobs = state.jobs.map(job => positions.has(job.id) ? {...job,position:positions.get(job.id)} : job);
  renderQueue();
  await api('/api/jobs/order',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_ids:jobIds})});
  await refresh();
}

function selectedQueueCaptures(){ return [...$('#queueCaptures').selectedOptions].map(item=>Number(item.value)); }

function bindDropzone(drop, input, url){
  drop.addEventListener('click',event => { if(!event.target.closest('button')) input.click(); else input.click(); });
  ['dragenter','dragover'].forEach(type => drop.addEventListener(type,event => {event.preventDefault();drop.classList.add('drag')}));
  ['dragleave','drop'].forEach(type => drop.addEventListener(type,event => {event.preventDefault();drop.classList.remove('drag')}));
  drop.addEventListener('drop',event => uploadFiles(url,event.dataTransfer.files));
  input.addEventListener('change',() => {uploadFiles(url,input.files);input.value=''});
}

function clearStrategyDropMarkers(){
  $$('.strategy-card').forEach(card => card.classList.remove('dragging','drop-before','drop-after'));
  document.body.classList.remove('strategy-dragging');
}

function clearJobDropMarkers(){
  $$('.job-row').forEach(row => row.classList.remove('dragging','drop-before','drop-after'));
  document.body.classList.remove('job-dragging');
}

document.addEventListener('dragstart', event => {
  const jobHandle = event.target.closest('.job-drag-handle');
  if(jobHandle){
    const row = jobHandle.closest('.job-row');
    draggedJobId = Number(row.dataset.jobId);
    jobDragActive = true;
    document.body.classList.add('job-dragging');
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', String(draggedJobId));
    requestAnimationFrame(() => row.classList.add('dragging'));
    return;
  }
  const handle = event.target.closest('.drag-handle');
  if(!handle) return;
  const card = handle.closest('.strategy-card');
  draggedStrategyId = Number(card.dataset.strategyId);
  strategyDragActive = true;
  document.body.classList.add('strategy-dragging');
  event.dataTransfer.effectAllowed = 'move';
  event.dataTransfer.setData('text/plain', String(draggedStrategyId));
  requestAnimationFrame(() => card.classList.add('dragging'));
});

document.addEventListener('dragover', event => {
  if(jobDragActive){
    const row = event.target.closest('.job-row.queued');
    if(!row || Number(row.dataset.jobId) === draggedJobId) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    $$('.job-row').forEach(item => item.classList.remove('drop-before','drop-after'));
    jobDropSide = event.clientY >= row.getBoundingClientRect().top + row.offsetHeight / 2 ? 'after' : 'before';
    row.classList.add(jobDropSide === 'after' ? 'drop-after' : 'drop-before');
    return;
  }
  if(!strategyDragActive) return;
  const card = event.target.closest('.strategy-card');
  if(!card || Number(card.dataset.strategyId) === draggedStrategyId) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = 'move';
  $$('.strategy-card').forEach(item => item.classList.remove('drop-before','drop-after'));
  strategyDropSide = event.clientY >= card.getBoundingClientRect().top + card.offsetHeight / 2 ? 'after' : 'before';
  card.classList.add(strategyDropSide === 'after' ? 'drop-after' : 'drop-before');
});

document.addEventListener('drop', async event => {
  if(jobDragActive){
    const targetRow = event.target.closest('.job-row.queued');
    if(!targetRow) return;
    event.preventDefault();
    const sourceId = draggedJobId;
    const targetId = Number(targetRow.dataset.jobId);
    const side = jobDropSide;
    clearJobDropMarkers();
    jobDragActive = false;
    draggedJobId = null;
    if(sourceId === targetId) return;
    const ordered = state.jobs.filter(job => job.status === 'queued').map(job => job.id);
    const sourceIndex = ordered.indexOf(sourceId);
    if(sourceIndex < 0) return;
    ordered.splice(sourceIndex,1);
    const targetIndex = ordered.indexOf(targetId);
    if(targetIndex < 0) return;
    ordered.splice(targetIndex + (side === 'after' ? 1 : 0),0,sourceId);
    try{ await saveJobOrder(ordered); toast('Queue order saved'); }catch(error){ toast(error.message,true); await refresh(); }
    return;
  }
  if(!strategyDragActive) return;
  const targetCard = event.target.closest('.strategy-card');
  if(!targetCard) return;
  event.preventDefault();
  const sourceId = draggedStrategyId;
  const targetId = Number(targetCard.dataset.strategyId);
  const side = strategyDropSide;
  clearStrategyDropMarkers();
  strategyDragActive = false;
  draggedStrategyId = null;
  if(sourceId === targetId) return;
  const ordered = [...state.strategies];
  const sourceIndex = ordered.findIndex(item => item.id === sourceId);
  if(sourceIndex < 0) return;
  const [moved] = ordered.splice(sourceIndex, 1);
  const targetIndex = ordered.findIndex(item => item.id === targetId);
  if(targetIndex < 0) return;
  ordered.splice(targetIndex + (side === 'after' ? 1 : 0), 0, moved);
  try{ await saveStrategyOrder(ordered); toast('Stage order saved'); }catch(error){ toast(error.message,true); await refresh(); }
});

document.addEventListener('dragend', () => {
  clearJobDropMarkers();
  jobDragActive = false;
  draggedJobId = null;
  clearStrategyDropMarkers();
  strategyDragActive = false;
  draggedStrategyId = null;
});

document.addEventListener('click', async event => {
  const wikiTarget = event.target.closest('[data-wiki-target]');
  if(wikiTarget){
    event.preventDefault();
    const targetId = wikiTarget.dataset.wikiTarget;
    navigate('help');
    requestAnimationFrame(() => {
      const section = document.getElementById(targetId);
      if(section){
        section.hidden = false;
        section.scrollIntoView({behavior:'smooth',block:'start'});
        $$('.wiki-toc a').forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${targetId}`));
      }
    });
    return;
  }
  const wikiLink = event.target.closest('.wiki-toc a');
  if(wikiLink){
    event.preventDefault();
    const section = document.querySelector(wikiLink.getAttribute('href'));
    if(section){
      section.scrollIntoView({behavior:'smooth',block:'start'});
      $$('.wiki-toc a').forEach(link => link.classList.toggle('active', link === wikiLink));
    }
    return;
  }
  const choice = event.target.closest('.queue-choice');
  if(choice){
    const select = $(`#${choice.dataset.selectId}`);
    const option = [...select.options].find(item => item.value === choice.dataset.value);
    if(option){
      option.selected = !option.selected;
      const selected = new Set([...select.selectedOptions].map(item => Number(item.value)));
      if(choice.dataset.selectId === 'queueCaptures') queueCaptureSelection = selected;
      else queueStrategySelection = selected;
      renderLaunchChoices();
    }
    return;
  }
  const selectAllButton = event.target.closest('[data-select-all]');
  if(selectAllButton){
    const select = $(`#${selectAllButton.dataset.selectAll}`);
    const shouldSelect = [...select.options].some(option => !option.selected);
    [...select.options].forEach(option => option.selected = shouldSelect);
    const selected = new Set([...select.selectedOptions].map(item => Number(item.value)));
    if(selectAllButton.dataset.selectAll === 'queueCaptures') queueCaptureSelection = selected;
    else queueStrategySelection = selected;
    renderLaunchChoices();
    return;
  }
  const addStage = event.target.closest('[data-add-mode]');
  if(addStage){
    const mode = addStage.dataset.addMode;
    const firstWordlist = state.wordlists.find(item => item.kind === 'wordlist')?.id || null;
    const firstRule = state.wordlists.find(item => item.kind === 'rule')?.id || null;
    const defaults = {
      known:{name:'Known results',config:{}},
      common:{name:'Common passwords',config:{}},
      pattern:{name:'Pattern Builder',config:{}},
      dictionary:{name:'Focused dictionary',config:{wordlist_id:firstWordlist}},
      rules:{name:'Dictionary + rules',config:{wordlist_id:firstWordlist,rule_id:firstRule}},
      hybrid:{name:'Hybrid suffix',config:{wordlist_id:firstWordlist,mask:'?d?d?d?d'}},
      mask:{name:'8-digit numeric mask',config:{mask:'?d?d?d?d?d?d?d?d',increment:false}}
    };
    const item = defaults[mode];
    if(!item) return;
    try{
      await api('/api/strategies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...item,mode})});
      await refresh();
      toast(`${item.name} added`);
      $('#strategyList').lastElementChild?.scrollIntoView({behavior:'smooth',block:'center'});
    }catch(error){ toast(error.message,true); }
    return;
  }
  const nav = event.target.closest('[data-nav]');
  if(nav){ event.preventDefault(); navigate(nav.dataset.nav); return; }
  const card = event.target.closest('.capture-card');
  if(card && !event.target.closest('.delete-capture') && !event.target.closest('.reprocess-capture') && !event.target.closest('.diagnostics-capture') && !event.target.closest('.verify-capture')){
    const id = Number(card.dataset.captureId);
    const capture = state.captures.find(item => item.id === id);
    if(capture?.fully_recovered){ toast('Already recovered · excluded from new queues'); return; }
    selectedCaptures.has(id) ? selectedCaptures.delete(id) : selectedCaptures.add(id);
    queueCaptureSelection = new Set(selectedCaptures);
    renderCaptures(); renderSelects(); return;
  }
  const del = event.target.closest('.delete-capture');
  if(del){
    const id = Number(del.closest('.capture-card').dataset.captureId);
    try{ await api(`/api/captures/${id}`,{method:'DELETE'}); selectedCaptures.delete(id); queueCaptureSelection?.delete(id); await refresh(); toast('Capture deleted'); }catch(error){ toast(error.message,true); }
    return;
  }
  const reprocess = event.target.closest('.reprocess-capture');
  if(reprocess){
    const id = Number(reprocess.closest('.capture-card').dataset.captureId);
    try{ const result = await api(`/api/captures/${id}/reprocess`,{method:'POST'}); toast(result.status === 'ready' ? `${result.networks} networks ready` : result.note,true); await refresh(); }catch(error){toast(error.message,true)}
    return;
  }
  const diagnostics = event.target.closest('.diagnostics-capture');
  if(diagnostics){
    const id = Number(diagnostics.closest('.capture-card').dataset.captureId);
    try{
      const result = await api(`/api/captures/${id}/diagnostics`);
      $('#diagnosticTitle').textContent = result.filename;
      $('#diagnosticOutput').textContent = result.diagnostics;
      $('#diagnosticDialog').showModal();
    }catch(error){ toast(error.message,true); }
    return;
  }
  const verifyCapture = event.target.closest('.verify-capture');
  if(verifyCapture){
    const card = verifyCapture.closest('.capture-card');
    const id = Number(card.dataset.captureId);
    const capture = state.captures.find(item => item.id === id);
    $('#verifyForm').dataset.captureId = String(id);
    $('#verifyTitle').textContent = capture?.filename || 'Verify WPA password';
    $('#verifyPassword').value = '';
    $('#verifyResult').hidden = true;
    $('#verifyResult').className = 'verify-result';
    $('#verifyResult').textContent = '';
    $('#verifyDialog').showModal();
    setTimeout(() => $('#verifyPassword').focus(),50);
    return;
  }
  const toggle = event.target.closest('.toggle');
  if(toggle){
    toggle.classList.toggle('on');
    const enabled = toggle.classList.contains('on');
    toggle.setAttribute('aria-pressed',String(enabled));
    $('span',toggle).textContent = enabled ? 'ON' : 'OFF';
    toggle.closest('.strategy-card').classList.toggle('disabled',!enabled);
    await updateStrategy(toggle.closest('.strategy-card'));
    await refresh();
    return;
  }
  const up = event.target.closest('.stage-up'); if(up){ await reorderStrategy(Number(up.closest('.strategy-card').dataset.strategyId),-1); return; }
  const down = event.target.closest('.stage-down'); if(down){ await reorderStrategy(Number(down.closest('.strategy-card').dataset.strategyId),1); return; }
  const sourceUp=event.target.closest('.source-up'); if(sourceUp){await reorderSource(Number(sourceUp.closest('.source-actions').dataset.sourceId),-1);return}
  const sourceDown=event.target.closest('.source-down'); if(sourceDown){await reorderSource(Number(sourceDown.closest('.source-actions').dataset.sourceId),1);return}
  const filterShort=event.target.closest('.filter-short-source');
  if(filterShort){
    const id=Number(filterShort.closest('.source-actions').dataset.sourceId);
    const source=state.wordlists.find(item=>item.id===id);
    if(!source)return;
    if(!confirm(`Create a WPA-ready copy of ${source.filename} and remove every candidate shorter than 8 bytes? The original file stays on disk.`))return;
    const original=filterShort.textContent;filterShort.disabled=true;filterShort.textContent='Filtering…';
    try{
      const result=await api(`/api/wordlists/${id}/filter-short`,{method:'POST'});
      toast(`${result.filename} · ${Number(result.removed_lines).toLocaleString()} short candidate${result.removed_lines===1?'':'s'} removed · ${Number(result.kept_lines).toLocaleString()} kept`);
      await refresh();
    }catch(error){toast(error.message,true)}finally{filterShort.disabled=false;filterShort.textContent=original}
    return;
  }
  const analyzeSource=event.target.closest('.analyze-source');
  if(analyzeSource){
    const id=Number(analyzeSource.closest('.source-actions').dataset.sourceId);
    analyzeSource.disabled=true;analyzeSource.textContent='Analyzing…';
    try{await api(`/api/wordlists/${id}/analyze`,{method:'POST'});await refresh();toast('Dictionary analysis started in the background')}catch(error){toast(error.message,true);analyzeSource.disabled=false;analyzeSource.textContent='Analyze'}
    return;
  }
  const doctorFix=event.target.closest('.doctor-fix');
  if(doctorFix){await applyDoctor(doctorFix.dataset.action,doctorFix);return}
  const runPreset=event.target.closest('.run-preset');
  if(runPreset){const id=Number(runPreset.closest('.preset-card').dataset.presetId);try{const result=await api(`/api/presets/${id}/queue`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({capture_ids:selectedQueueCaptures(),capture_sort:$('#queuePriority').value})});toast(`${result.preset}: ${result.created} jobs queued`);navigate('queue');await refresh()}catch(error){toast(error.message,true)}return}
  const deletePreset=event.target.closest('.delete-preset');
  if(deletePreset){const id=Number(deletePreset.closest('.preset-card').dataset.presetId);if(confirm('Delete this custom template?')){try{await api(`/api/presets/${id}`,{method:'DELETE'});await refresh();toast('Template deleted')}catch(error){toast(error.message,true)}}return}
  const jobLog = event.target.closest('.job-log');
  if(jobLog){
    const id = Number(jobLog.closest('.job-row').dataset.jobId);
    try{
      const result = await api(`/api/jobs/${id}/log`);
      $('#diagnosticTitle').textContent = `Job #${id} process log`;
      $('#diagnosticOutput').textContent = `${result.error ? `STATUS: ${result.error}\n\n` : ''}COMMAND\n${result.command.join(' ')}\n\nOUTPUT\n${result.output}`;
      $('#diagnosticDialog').showModal();
    }catch(error){ toast(error.message,true); }
    return;
  }
  const deleteJob = event.target.closest('.delete-job');
  if(deleteJob){
    const id = Number(deleteJob.closest('.job-row').dataset.jobId);
    try{ await api(`/api/jobs/${id}`,{method:'DELETE'}); await refresh(); toast(`Job #${id} deleted`); }catch(error){ toast(error.message,true); }
    return;
  }
  const action = event.target.closest('.job-action');
  if(action){
    const id=Number(action.closest('.job-row').dataset.jobId),label=action.textContent;action.disabled=true;
    if(action.dataset.action==='retry')action.textContent='Retrying…';
    try{await api(`/api/jobs/${id}/${action.dataset.action}`,{method:'POST'});await refresh();if(action.dataset.action==='retry')toast(`Job #${id} returned to the queue`)}catch(error){toast(error.message,true);action.disabled=false;action.textContent=label}
    return;
  }
  const copy = event.target.closest('.copy-result');
  if(copy){ await navigator.clipboard.writeText(copy.dataset.password); toast('Password copied'); return; }
});

document.addEventListener('change', async event => {
  if(event.target.matches('#queueOrder,#queueWorkload,#queuePriority')){
    if(event.target.id === 'queueOrder') localStorage.setItem('newfpv-queue-order',event.target.value);
    if(event.target.id === 'queuePriority'){
      localStorage.setItem('newfpv-queue-priority',event.target.value);
      renderSelects();
    }else updateLaunchSummary();
    return;
  }
  const card = event.target.closest('.strategy-card');
  if(card && event.target.matches('[data-config]')){ try{await updateStrategy(card);toast('Stage updated')}catch(error){toast(error.message,true)} }
});

document.addEventListener('focusout', async event => {
  const card = event.target.closest('.strategy-card');
  if(card && event.target.matches('[data-name]')){ try{await updateStrategy(card)}catch(error){toast(error.message,true)} }
});

$('#captureUploadButton').onclick = () => $('#captureInput').click();
$('#wordlistUploadButton').onclick = () => $('#wordlistInput').click();
$('#analyzeAllSources').onclick = async event => {
  const button=event.currentTarget;button.disabled=true;
  try{const result=await api('/api/wordlists/analyze-all',{method:'POST'});toast(result.started.length?`${result.started.length} dictionary analysis job${result.started.length===1?'':'s'} started`:'All dictionaries are already being analyzed');await refresh()}catch(error){toast(error.message,true)}finally{button.disabled=false}
};
$('#cascadeDedupButton').onclick = openCascadeDedup;
$('#runCascadeDedup').onclick = runCascadeDedup;
$('#scanSourcesButton').onclick = async () => {
  try{
    const result = await api('/api/wordlists/scan', {method:'POST'});
    toast(result.imported.length ? `Linked ${result.imported.length} local source${result.imported.length === 1 ? '' : 's'}` : 'Local source folders are already synchronized');
    await refresh();
  }catch(error){ toast(error.message, true); }
};
$('#clearFinishedJobs').onclick = async () => {
  try{
    const result = await api('/api/jobs/finished',{method:'DELETE'});
    await refresh();
    toast(result.deleted ? `${result.deleted} finished job${result.deleted === 1 ? '' : 's'} removed` : 'No finished jobs to remove');
  }catch(error){ toast(error.message,true); }
};
$('#queueSort').onchange=async event=>{
  const select=event.target,mode=select.value;select.disabled=true;
  try{const result=await api('/api/jobs/sort',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});localStorage.setItem('newfpv-queue-priority',mode);$('#queuePriority').value=mode;await refresh();toast(`${result.updated} waiting jobs sorted`)}catch(error){toast(error.message,true)}finally{select.disabled=false}
};
$('#pauseAllJobs').onclick=async()=>{
  const button=$('#pauseAllJobs'),paused=Boolean(state.config.queue_paused);button.disabled=true;
  try{const result=await api(`/api/queue/${paused?'resume-all':'pause-all'}`,{method:'POST'});await refresh();toast(result.queue_paused?'Queue paused · no new jobs will start':'Queue resumed')}catch(error){toast(error.message,true)}finally{button.disabled=false}
};
$('#pauseLocalGpu').onclick=async()=>{
  const button=$('#pauseLocalGpu'),paused=Boolean(state.config.local_queue_paused);button.disabled=true;
  try{const result=await api(`/api/queue/local/${paused?'resume':'pause'}`,{method:'POST'});await refresh();toast(result.local_queue_paused?'RTX 3060 lane paused':'RTX 3060 lane resumed')}catch(error){toast(error.message,true)}finally{button.disabled=false}
};
$('#liveWorkload').onchange=async event=>{
  const select=event.target,workload=Number(select.value);select.disabled=true;
  try{const result=await api('/api/queue/workload',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({workload})});await refresh();toast(result.live_jobs?.length?`W${workload} applied instantly · position preserved`:`Queue profile changed to W${workload}`)}catch(error){toast(error.message,true)}finally{select.disabled=false}
};
$('#lanGpuConsoles').addEventListener('change',async event=>{
  const card=event.target.closest('[data-worker]');if(!card)return;
  let payload=null;
  if(event.target.classList.contains('remote-workload'))payload={workload:Number(event.target.value)};
  if(event.target.classList.contains('remote-cpu-profile'))payload={cpu_profile:event.target.value};
  if(!payload)return;
  event.target.disabled=true;
  try{const result=await api(`/api/lan/workers/${encodeURIComponent(card.dataset.worker)}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});await refresh();toast(`${card.dataset.worker}: profile saved${result.gpu_profile_live?' · GPU changed live':''}${result.cpu_profile_applies_next_job?' · CPU applies next job':''}`)}catch(error){toast(error.message,true)}finally{event.target.disabled=false}
});
$('#lanGpuConsoles').addEventListener('click',async event=>{
  const button=event.target.closest('.remote-pause'),card=event.target.closest('[data-worker]');if(!button||!card)return;
  const worker=state.lan_workers.find(item=>item.name===card.dataset.worker);if(!worker)return;
  button.disabled=true;
  try{await api(`/api/lan/workers/${encodeURIComponent(worker.name)}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({paused:!Boolean(worker.paused)})});await refresh();toast(`${worker.name} ${worker.paused?'resumed':'paused'}`)}catch(error){toast(error.message,true)}finally{button.disabled=false}
});
bindDropzone($('#captureDrop'),$('#captureInput'),'/api/captures');
bindDropzone($('#wordlistDrop'),$('#wordlistInput'),'/api/wordlists');
$('#captureSearch').addEventListener('input',renderCaptures);
$('#resultSearch').addEventListener('input',renderResults);
$('#helpSearch').addEventListener('input', event => {
  const query = event.target.value.trim().toLowerCase();
  let visible = 0;
  $$('.wiki-section').forEach(section => {
    const matches = !query || `${section.dataset.help || ''} ${section.textContent}`.toLowerCase().includes(query);
    section.hidden = !matches;
    if(matches) visible++;
  });
  $('#wikiEmpty').classList.toggle('show', visible === 0);
});

$('#savePreset').onclick=()=>$('#presetDialog').showModal();
$('#createPreset').onclick=async event=>{
  event.preventDefault();
  const available={
    known:$('#presetKnown').checked?{kind:'known'}:null,
    common:$('#presetCommon').checked?{kind:'common'}:null,
    mask:$('#presetMaskEnabled').checked?{kind:'mask',mask:$('#presetMask').value.trim(),optimized:true}:null,
    dictionaries:$('#presetDictionaries').checked?{kind:'all_wordlists',mode:'dictionary'}:null,
    rules:$('#presetRules').checked?{kind:'all_rules'}:null
  };
  const sequences={mask_first:['known','common','mask','dictionaries','rules'],dictionary_first:['known','common','dictionaries','rules','mask'],mask_last:['known','common','dictionaries','mask','rules']};
  const stages=sequences[$('#presetSequence').value].map(key=>available[key]).filter(Boolean);
  const payload={name:$('#presetName').value.trim(),description:'Custom reusable recovery plan',config:{order:$('#presetOrder').value,workload:Number($('#presetWorkload').value),stages}};
  try{await api('/api/presets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});$('#presetDialog').close();await refresh();toast('Custom template saved')}catch(error){toast(error.message,true)}
};

$('#verifyForm').addEventListener('submit', async event => {
  if(event.submitter?.id !== 'verifySubmit') return;
  event.preventDefault();
  const captureId = Number(event.currentTarget.dataset.captureId);
  const password = $('#verifyPassword').value;
  const button = $('#verifySubmit');
  const resultBox = $('#verifyResult');
  button.disabled = true;
  button.textContent = 'Verifying…';
  resultBox.hidden = false;
  resultBox.className = 'verify-result working';
  resultBox.textContent = 'Hashcat is checking the password locally…';
  try{
    const result = await api(`/api/captures/${captureId}/verify`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
    if(result.valid){
      const networks = result.matches.map(match => match.essid).join(', ');
      resultBox.className = 'verify-result valid';
      resultBox.innerHTML = `<b>Valid password</b><code>${esc(password)}</code><span>${esc(networks)}${result.skipped_jobs ? ` · ${result.skipped_jobs} queued job${result.skipped_jobs === 1 ? '' : 's'} skipped` : ''}</span>`;
      toast(`Valid password for ${networks}`);
      await refresh();
    }else{
      resultBox.className = 'verify-result invalid';
      resultBox.innerHTML = '<b>No match</b><span>This password does not verify against any network in the capture.</span>';
    }
  }catch(error){
    resultBox.className = 'verify-result invalid';
    resultBox.innerHTML = `<b>Verification failed</b><span>${esc(error.message)}</span>`;
  }finally{
    button.disabled = false;
    button.textContent = 'Verify password';
  }
});

$('#startQueue').onclick = async () => {
  const capture_ids = selectedQueueCaptures();
  const strategy_ids = [...$('#queueStrategies').selectedOptions].map(item => Number(item.value));
  const order=$('#queueOrder').value,workload=Number($('#queueWorkload').value),capture_sort=$('#queuePriority').value;
  try{ const result = await api('/api/queue',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({capture_ids,strategy_ids,order,workload,capture_sort})}); toast(`${result.created} jobs queued · ${titleCase(result.order)}`); navigate('queue'); await refresh(); }catch(error){toast(error.message,true)}
};

$('#saveSettings').onclick = async () => {
  const button=$('#saveSettings');
  const payload = {hashcat_path:$('#hashcatPath').value.trim(),hcxpcapngtool_path:$('#hcxPath').value.trim(),host:$('#hostSetting').value.trim(),port:Number($('#portSetting').value),max_workers:Number($('#workerSetting').value),workload_profile:Number($('#workloadSetting').value),temperature_abort:Number($('#temperatureSetting').value),lan_enabled:$('#lanEnabled').checked,lan_token:$('#lanToken').value.trim(),lan_job_timeout:Number($('#lanTimeout').value),notifications_windows:$('#windowsNotifications').checked,notifications_telegram:$('#telegramNotifications').checked,telegram_bot_token:$('#telegramBotToken').value.trim(),telegram_chat_id:$('#telegramChatId').value.trim(),telegram_file_intake:$('#telegramFileIntake').checked,notify_password_found:$('#notifyPassword').checked,notify_overheat:$('#notifyOverheat').checked,notify_worker_error:$('#notifyWorker').checked,notify_queue_complete:$('#notifyQueue').checked,remote_access_enabled:$('#remoteAccessEnabled').checked,remote_username:$('#remoteUsername').value.trim(),remote_password:$('#remotePassword').value,remote_https_url:$('#remoteHttpsUrl').value.trim(),self_signed_https_enabled:$('#selfSignedHttps').checked,https_port:Number($('#httpsPort').value)};
  button.disabled=true;
  try{
    const result=await api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    settingsDirty=false;state.config=result.config;$('#remotePassword').value='';
    button.classList.remove('settings-dirty');button.innerHTML=`${icon('check')}Save changes`;
    renderSettings();toast('Settings saved. Restart the app if host or port changed.');await refresh();
  }catch(error){toast(error.message,true)}finally{button.disabled=false}
};

$('#runDoctor').onclick=event=>runDoctor(event.currentTarget);
$('#doctorFixAll').onclick=event=>applyDoctor('all',event.currentTarget);
$('#telegramNotifications').onchange=event=>{$('#telegramBotToken').disabled=!event.target.checked;$('#telegramChatId').disabled=!event.target.checked;$('#telegramFileIntake').disabled=!event.target.checked};
const settingsPage=$('[data-page="settings"]');
settingsPage.addEventListener('input',event=>{if(event.target.matches('input,select'))markSettingsDirty()});
settingsPage.addEventListener('change',event=>{if(event.target.matches('input,select'))markSettingsDirty()});
$('#testWindowsNotification').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{await api('/api/notifications/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel:'windows'})});toast('Windows test notification sent')}catch(error){toast(error.message,true)}finally{button.disabled=false}};
$('#testTelegramNotification').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{await api('/api/notifications/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel:'telegram'})});toast('Telegram test message sent')}catch(error){toast(error.message,true)}finally{button.disabled=false}};
$('#testAllNotifications').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{const result=await api('/api/notifications/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel:'all'})});toast(`Test sent: ${result.sent.join(' + ')}`)}catch(error){toast(error.message,true)}finally{button.disabled=false}};
$('#runBenchmark').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{await api('/api/benchmark',{method:'POST'});toast('WPA 22000 benchmark started');pollBenchmark()}catch(error){toast(error.message,true)}finally{button.disabled=false}};
$('#checkPublicAddress').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{const result=await api('/api/remote/status');const box=$('#remoteStatus');const address=result.https_url||result.url;box.innerHTML=address?`<b>${esc(address)}</b><span>${result.self_signed_https_url?'Self-signed HTTPS is running. Forward its port separately; certificate warnings are expected.':result.https_url?'Trusted HTTPS is ready for Telegram Mini App.':result.enabled&&result.listening_publicly?'HTTP listener is reachable locally; use the LAN address at home and public address outside your Wi-Fi.':'Enable remote access, save and restart before exposing the listener.'}</span>`:`<b>Public address unavailable</b><span>${esc(result.error||'Check the internet connection.')}</span>`}catch(error){toast(error.message,true)}finally{button.disabled=false}};

$('#liveCpuProfile').onchange = async event => {
  const previous=state.config.cpu_profile||'off',profile=event.target.value;
  try{
    const result=await api('/api/queue/cpu-profile',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile})});
    toast(`CPU profile: ${titleCase(profile)} · ${result.updated_jobs} waiting job${result.updated_jobs===1?'':'s'} updated${result.local_cpu_available?'':' · coordinator CPU backend unavailable; LAN workers may still use CPU'}${result.active_jobs_unchanged?' · active job keeps its current devices':''}`);
    await refresh();
  }catch(error){event.target.value=previous;toast(error.message,true)}
};

$('#restoreBackup').onclick = () => $('#backupFile').click();
$('#backupFile').onchange = async event => {
  const file = event.target.files?.[0];
  if(!file) return;
  if(!confirm('Restore settings, verified results and handshake method memory from this backup? Existing records will be kept.')){ event.target.value=''; return; }
  const button=$('#restoreBackup');button.disabled=true;button.textContent='Restoring…';
  const form=new FormData();form.append('file',file);
  try{
    const result=await api('/api/backup/restore',{method:'POST',body:form});
    toast(`Backup restored · ${result.results} new result${result.results===1?'':'s'} · ${result.attempts} new method record${result.attempts===1?'':'s'}`);
    await refresh();
  }catch(error){toast(error.message,true)}finally{button.disabled=false;button.innerHTML=`${icon('upload')}Restore backup`;event.target.value=''}
};

function applyAccent(index){
  const accent = accents[index % accents.length];
  document.documentElement.style.setProperty('--accent',accent[1]);
  document.documentElement.style.setProperty('--accent-rgb',accent[2]);
  localStorage.setItem('newfpv-accent',String(index % accents.length));
}
let accentIndex = Number(localStorage.getItem('newfpv-accent') || 0);
applyAccent(accentIndex);
const savedQueueOrder = localStorage.getItem('newfpv-queue-order') || 'capture_first';
if(['strategy_first','capture_first'].includes(savedQueueOrder)) $('#queueOrder').value = savedQueueOrder;
const savedQueuePriority = localStorage.getItem('newfpv-queue-priority') || 'likely_fastest';
if(['current','likely_fastest','factory_first','simple_first','fewest_networks','alphabetical','newest','oldest'].includes(savedQueuePriority)){
  $('#queuePriority').value=savedQueuePriority;
  if(savedQueuePriority!=='current') $('#queueSort').value=savedQueuePriority;
}
$('#accentSwitch').onclick = () => applyAccent(++accentIndex);
$('#telemetryChart').addEventListener('mousemove',event=>{const samples=(state.telemetry||[]).slice(-120),rect=event.currentTarget.getBoundingClientRect(),left=44,right=54;if(!samples.length)return;const ratio=Math.max(0,Math.min(1,(event.clientX-rect.left-left)/Math.max(1,rect.width-left-right)));telemetryHoverIndex=Math.round(ratio*(samples.length-1));drawTelemetry()});
$('#telemetryChart').addEventListener('mouseleave',()=>{telemetryHoverIndex=null;drawTelemetry()});
setInterval(() => $('#clock').textContent = new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'}),1000);
window.addEventListener('hashchange',() => {
  const page = location.hash.slice(1);
  if(document.querySelector(`[data-page="${page}"]`)) navigate(page);
});
navigate(activePage);
refresh(false);
refreshTimer = setInterval(() => refresh(true),3000);
