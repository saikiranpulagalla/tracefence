/* TraceFence Runtime Inspector: fixed local demonstration controls only. */

state.demoMode = false;
state.demoSessionId = null;
state.demoBusy = false;
state.demoAutoRunning = false;
state.events = [];
state.selectedAction = null;

const demoPhases = [
  ['WAITING_STALE_WORKER', 'worker waiting'],
  ['SUPERSEDED', 'scope superseded'],
  ['STALE_DENIED', 'stale action denied'],
  ['RECOVERY_COMMITTED', 'replacement committed'],
  ['PROOF_AVAILABLE', 'proof built'],
];

async function demoApi(path, options = {}) {
  const {headers = {}, ...rest} = options;
  const finalHeaders = {...headers};
  if (rest.body !== undefined && !finalHeaders['Content-Type']) {
    finalHeaders['Content-Type'] = 'application/json';
  }
  const response = await fetch(`/v1/demo${path}`, {
    ...rest,
    headers: finalHeaders,
    credentials: 'same-origin',
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    let errorCode = null;
    try {
      const body = await response.json();
      detail = body?.error?.message ?? body?.detail ?? detail;
      errorCode = body?.error?.code ?? null;
    } catch {
      // Keep the status-only message for non-JSON failures.
    }
    const error = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    error.status = response.status;
    error.code = errorCode;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function renderDemoTimeline() {
  if (!state.demoMode) {
    const commands = state.graph?.commands ?? [];
    $('timeline').innerHTML = commands.length ? commands.map(command => `
      <div class="event">
        <strong>${escapeHtml(command.type)} · ${short(command.target_node_id)}</strong>
        <small>${escapeHtml(command.reason_code)} · scope v${command.from_version} → v${command.to_version} · ${new Date(command.created_at).toLocaleTimeString()}</small>
      </div>`).join('') : '<p class="muted">No control commands.</p>';
    return;
  }
  $('timeline').innerHTML = state.events.length ? [...state.events].reverse().map(event => `
    <div class="event ${escapeHtml(event.event_type)}" ${event.action_id ? `data-action="${escapeHtml(event.action_id)}" tabindex="0"` : ''}>
      <strong>#${event.sequence} · ${escapeHtml(event.event_type)}</strong>
      <small>${event.node_id ? `node ${short(event.node_id)} · ` : ''}${event.command_id ? `command ${short(event.command_id)} · ` : ''}${event.action_id ? `action ${short(event.action_id)} · ` : ''}${escapeHtml(event.reason_code ?? '')}</small>
      <small>${new Date(event.occurred_at).toLocaleTimeString()}${event.snapshot_version ? ` · scope v${event.snapshot_version} → v${event.authoritative_version}` : ''}</small>
    </div>`).join('') : '<p class="muted">Start a scenario to create runtime events.</p>';
  bindActionSelectors();
}

function renderDemoActions() {
  $('actions').innerHTML = state.actions.length ? state.actions.map(action => `
    <tr class="action-row ${state.selectedAction?.id === action.id ? 'selected' : ''}" data-action="${escapeHtml(action.id)}" tabindex="0">
      <td>${new Date(action.attempted_at).toLocaleTimeString()}</td>
      <td>${short(action.node_id)}</td>
      <td>${escapeHtml(action.tool_name)}</td>
      <td class="${escapeHtml(action.decision)}">${escapeHtml(action.decision)}</td>
      <td>${escapeHtml(action.denial_reason ?? '—')}</td>
      <td>${action.committed ? 'yes' : 'no'}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="muted">No actions.</td></tr>';
  bindActionSelectors();
}

function bindActionSelectors() {
  document.querySelectorAll('[data-action]').forEach(row => {
    if (row.dataset.actionBound === 'true') return;
    row.dataset.actionBound = 'true';
    const choose = () => selectDemoAction(row.dataset.action);
    row.addEventListener('click', choose);
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        choose();
      }
    });
  });
}

function selectDemoAction(actionId) {
  state.selectedAction = state.actions.find(action => action.id === actionId) ?? null;
  const action = state.selectedAction;
  const explanation = action?.decision_explanation;
  $('actionInspector').innerHTML = action && explanation ? `
    <div class="verdict ${escapeHtml(action.decision)}">${escapeHtml(action.decision)}${action.denial_reason ? ` · ${escapeHtml(action.denial_reason)}` : ''}</div>
    <p class="muted">${escapeHtml(action.tool_name)} · action ${short(action.id)} · node ${short(action.node_id)}</p>
    ${(explanation.checks ?? []).map(check => `
      <div class="decision-check">
        <span>${escapeHtml(check.name)}${check.reason ? ` · ${escapeHtml(check.reason)}` : ''}</span>
        <strong class="${escapeHtml(check.outcome)}">${escapeHtml(check.outcome)}</strong>
      </div>`).join('')}
    <div class="decision-check"><span>idempotency</span><strong>${escapeHtml(explanation.idempotency)}</strong></div>
    <div class="decision-check"><span>side effect committed</span><strong class="${action.committed ? 'FAIL' : 'PASS'}">${action.committed ? 'YES' : 'NO'}</strong></div>
    ${action.matched_scope_id ? `<p class="muted">snapshot v${action.matched_snapshot_version} · live v${action.matched_live_version} ${escapeHtml(action.matched_live_status)} · scope ${short(action.matched_scope_id)}</p>` : ''}`
    : 'Select an action ledger row.';
  renderDemoActions();
}

function renderDemoProof() {
  const proof = state.proof;
  if (!proof) {
    $('proof').innerHTML = '<p class="muted">Build proof after the replacement commits.</p>';
    return;
  }
  $('proof').innerHTML = `
    <div class="verdict ${escapeHtml(proof.overall_verdict)}">overall ${escapeHtml(proof.overall_verdict)}</div>
    <p><strong class="${escapeHtml(proof.runtime_verdict)}">runtime ${escapeHtml(proof.runtime_verdict)}</strong> · <strong class="${escapeHtml(proof.telemetry_verdict)}">telemetry ${escapeHtml(proof.telemetry_verdict)}</strong></p>
    <p class="muted">SigNoz is disabled in local demo mode. It supplies evidence, never action authority.</p>
    <div class="proof-grid">
      <div class="proof-item"><span>Blocked stale</span><strong>${proof.stale_action_attempts}</strong></div>
      <div class="proof-item"><span>Stale committed</span><strong>${proof.stale_actions_committed}</strong></div>
      <div class="proof-item"><span>Sibling impact</span><strong>${proof.unrelated_branches_interrupted}</strong></div>
      <div class="proof-item"><span>Replacement</span><strong class="${escapeHtml(proof.replacement_lineage_verdict)}">${escapeHtml(proof.replacement_lineage_verdict)}</strong></div>
    </div>`;
}

renderTimeline = renderDemoTimeline;
renderActions = renderDemoActions;
renderProof = renderDemoProof;

function renderDemoControls(phase = null, transitions = []) {
  const currentIndex = demoPhases.findIndex(([name]) => name === phase);
  $('demoProgress').innerHTML = demoPhases.map(([_name, label], index) => {
    const css = index < currentIndex ? 'done' : index === currentIndex ? 'current' : '';
    return `<div class="demo-step ${css}">${index + 1}. ${escapeHtml(label)}</div>`;
  }).join('');
  const enabled = new Set(transitions);
  $('demoStart').disabled = state.demoBusy;
  $('demoAuto').disabled = state.demoBusy || state.demoAutoRunning;
  $('demoSupersede').disabled = state.demoBusy || !enabled.has('SUPERSEDE');
  $('demoRelease').disabled = state.demoBusy || !enabled.has('RELEASE_STALE_WORKER');
  $('demoReplacement').disabled = state.demoBusy || !enabled.has('RUN_REPLACEMENT');
  $('demoProof').disabled = state.demoBusy || !enabled.has('BUILD_PROOF');
  $('demoReset').disabled = state.demoBusy || !state.demoSessionId;
}

function applyDemoSnapshot(snapshot) {
  state.demoSessionId = snapshot.session_id;
  state.runId = snapshot.run_id;
  state.graph = snapshot.graph;
  state.events = snapshot.events ?? [];
  state.services = snapshot.services ?? [];
  state.actions = [snapshot.stale_action, snapshot.replacement_action].filter(Boolean);
  state.violations = [];
  state.proof = snapshot.proof;
  const selectedId = state.selectedAction?.id;
  state.selectedAction = state.actions.find(action => action.id === selectedId)
    ?? state.actions.find(action => action.decision === 'DENY')
    ?? state.actions[0]
    ?? null;
  renderGraph(); renderDemoTimeline(); renderDemoActions(); renderServices(); renderViolations(); renderDemoProof(); renderMetrics();
  if (state.selectedAction) selectDemoAction(state.selectedAction.id);
  renderDemoControls(snapshot.phase, snapshot.allowed_transitions ?? []);
}

function applyCheckResult(result) {
  state.runId = result.run_id;
  state.graph = result.graph;
  state.events = result.events ?? [];
  state.services = result.services ?? [];
  state.actions = result.actions ?? [];
  state.violations = [];
  state.proof = null;
  state.selectedAction = state.actions.find(action => action.decision === 'DENY') ?? state.actions[0] ?? null;
  renderGraph(); renderDemoTimeline(); renderDemoActions(); renderServices(); renderViolations(); renderDemoProof(); renderMetrics();
  if (state.selectedAction) selectDemoAction(state.selectedAction.id);
  const decisions = state.actions.map(action => `${action.decision}${action.denial_reason ? ` ${action.denial_reason}` : ''}`).join(' · ');
  $('demoCheckResult').textContent = `${result.status}: ${result.expected}${decisions ? ` · ${decisions}` : ''}`;
}

async function runFixedCheck() {
  if (state.demoBusy) return;
  state.demoBusy = true;
  $('demoRunCheck').disabled = true;
  const scenario = $('demoCheckScenario').value;
  $('demoCheckResult').textContent = `Running ${scenario} through the authoritative services…`;
  try {
    let result = await demoApi(`/checks/${scenario}/run`, {method: 'POST'});
    if (result.status === 'WAITING_FOR_LEASE_EXPIRY') {
      const readyAt = new Date(result.ready_at).getTime();
      while (Date.now() <= readyAt) {
        const remaining = Math.max(0, readyAt - Date.now());
        $('demoCheckResult').textContent = `Worker remains paused; authoritative lease expires in ${(remaining / 1000).toFixed(1)}s…`;
        await new Promise(resolve => setTimeout(resolve, Math.min(500, remaining + 20)));
      }
      result = await demoApi(`/checks/lease-expiry/${result.check_id}/finish`, {method: 'POST'});
    }
    applyCheckResult(result);
  } finally {
    state.demoBusy = false;
    $('demoRunCheck').disabled = false;
  }
}

async function loadDemoSessions() {
  const sessions = await demoApi('/sessions');
  $('demoSessions').innerHTML = sessions.length ? sessions.map(session => `
    <option value="${escapeHtml(session.session_id)}" ${session.session_id === state.demoSessionId ? 'selected' : ''}>${escapeHtml(session.phase)} · ${short(session.run_id)}</option>`).join('') : '<option value="">No sessions yet</option>';
}

async function startDemo() {
  if (state.demoBusy) return;
  state.demoBusy = true;
  renderDemoControls();
  $('demoFeedback').textContent = 'Registering nodes and starting the real waiting worker…';
  try {
    applyDemoSnapshot(await demoApi('/scenarios/stale-supersession/start', {method: 'POST'}));
    await loadDemoSessions();
    $('demoFeedback').textContent = 'Worker is checkpointed immediately before restart_postgres.';
  } finally {
    state.demoBusy = false;
  }
}

async function transitionDemo(path, message) {
  if (!state.demoSessionId || state.demoBusy) return;
  state.demoBusy = true;
  $('demoFeedback').textContent = message;
  try {
    applyDemoSnapshot(await demoApi(`/sessions/${state.demoSessionId}/${path}`, {method: 'POST'}));
    await loadDemoSessions();
  } finally {
    state.demoBusy = false;
  }
}

$('demoStart').addEventListener('click', () => startDemo().catch(error => { $('demoFeedback').textContent = error.message; }));
$('demoSupersede').addEventListener('click', () => transitionDemo('supersede', 'Superseding the PostgreSQL branch…'));
$('demoRelease').addEventListener('click', () => transitionDemo('release-stale-worker', 'Releasing the stale worker into the Action Gateway…'));
$('demoReplacement').addEventListener('click', () => transitionDemo('run-replacement', 'Executing the exact correction manifest…'));
$('demoProof').addEventListener('click', () => transitionDemo('proof', 'Building runtime proof…'));
$('demoAuto').addEventListener('click', async () => {
  if (state.demoAutoRunning) return;
  state.demoAutoRunning = true;
  try {
    await startDemo();
    await new Promise(resolve => setTimeout(resolve, 600));
    await transitionDemo('supersede', 'Superseding the stale branch…');
    await new Promise(resolve => setTimeout(resolve, 600));
    await transitionDemo('release-stale-worker', 'Releasing the stale worker…');
    await new Promise(resolve => setTimeout(resolve, 600));
    await transitionDemo('run-replacement', 'Running the exact replacement…');
    await new Promise(resolve => setTimeout(resolve, 600));
    await transitionDemo('proof', 'Building authoritative proof…');
    $('demoFeedback').textContent = 'Scenario complete: runtime VERIFIED; external telemetry UNAVAILABLE.';
  } catch (error) {
    $('demoFeedback').textContent = error.message;
  } finally {
    state.demoAutoRunning = false;
  }
});
$('demoReset').addEventListener('click', async () => {
  if (!state.demoSessionId) return;
  await demoApi(`/sessions/${state.demoSessionId}/reset`, {method: 'POST'});
  state.demoSessionId = null; state.graph = null; state.actions = []; state.events = []; state.services = []; state.proof = null; state.selectedAction = null;
  renderGraph(); renderDemoTimeline(); renderDemoActions(); renderServices(); renderDemoProof(); renderMetrics(); renderDemoControls();
  await loadDemoSessions();
  $('demoFeedback').textContent = 'View reset. Prior authoritative runs remain in SQLite.';
});
$('demoSessions').addEventListener('change', async event => {
  if (event.target.value) applyDemoSnapshot(await demoApi(`/sessions/${event.target.value}`));
});
$('demoRunCheck').addEventListener('click', () => runFixedCheck().catch(error => { $('demoCheckResult').textContent = error.message; }));

async function initializeRuntimeInspector() {
  try {
    const bootstrap = await demoApi('/bootstrap');
    if (!bootstrap.enabled) return;
    state.demoMode = true;
    $('autoRefresh').value = 'off';
    $('demoWorkspace').hidden = false;
    $('adminToolbar').hidden = true;
    $('adminControls').hidden = true;
    $('timelineHeading').textContent = 'Authoritative runtime event timeline';
    const checks = bootstrap.scenarios.filter(name => name !== 'stale-supersession');
    $('demoCheckScenario').innerHTML = checks.map(name =>
      `<option value="${escapeHtml(name)}">${escapeHtml(name.replaceAll('-', ' '))}</option>`
    ).join('');
    await loadDemoSessions();
    renderDemoControls();
    setInterval(() => {
      if (state.demoSessionId && !state.demoBusy) {
        demoApi(`/sessions/${state.demoSessionId}`).then(applyDemoSnapshot).catch(console.error);
      }
    }, 1000);
  } catch (error) {
    if (error.status !== 404) console.error(error);
  }
}

initializeRuntimeInspector();
