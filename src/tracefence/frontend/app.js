const state = {
  runId: null,
  graph: null,
  actions: [],
  services: [],
  violations: [],
  selectedNode: null,
  proof: null,
  refreshInFlight: false,
  refreshSequence: 0,
  proofCommandId: null,
  proofFetchedAt: 0,
  refreshController: null,
  commandSubmitting: false,
};

const $ = id => document.getElementById(id);
const short = id => id ? `${id.slice(0, 8)}…` : "—";
const operatorKey = () => $('operatorKey').value.trim();

function clearProtectedState({clearRun = true} = {}) {
  state.refreshController?.abort();
  state.refreshSequence += 1;
  state.refreshInFlight = false;
  if (clearRun) state.runId = null;
  state.graph = null;
  state.actions = [];
  state.services = [];
  state.violations = [];
  state.selectedNode = null;
  state.proof = null;
  state.proofCommandId = null;
  state.proofFetchedAt = 0;
  $('nodeInspector').textContent = 'Select a graph node.';
  renderGraph();
  renderTimeline();
  renderActions();
  renderServices();
  renderViolations();
  renderProof();
  renderMetrics();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

async function api(path, options = {}, {auth = true, signal} = {}) {
  const {headers = {}, ...rest} = options;
  const finalHeaders = {...headers};
  if (rest.body !== undefined && !finalHeaders['Content-Type']) {
    finalHeaders['Content-Type'] = 'application/json';
  }
  if (auth) {
    const key = operatorKey();
    if (!key) throw new Error('Enter the operator key to access protected control-plane data.');
    finalHeaders['X-Operator-Key'] = key;
  }
  const response = await fetch(path, {...rest, headers: finalHeaders, signal});
  if (!response.ok) {
    let body;
    try { body = await response.json(); }
    catch { body = {detail: await response.text()}; }
    const detail = body?.error?.message ?? body?.detail ?? `HTTP ${response.status}`;
    const error = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    error.status = response.status;
    if (response.status === 401 && auth) clearProtectedState();
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

async function readiness(signal) {
  const response = await fetch('/readyz', {signal});
  let payload = {};
  try { payload = await response.json(); } catch { payload = {}; }
  return {ready: response.ok, payload};
}

function renderHealth(result) {
  const badge = $('health');
  if (result.ready) {
    badge.textContent = 'control plane ready';
    badge.classList.remove('error');
    return;
  }
  const degraded = [];
  if (result.payload?.database !== 'ready') degraded.push('database');
  if (result.payload?.control_runtime !== 'ready') degraded.push('runtime');
  if (result.payload?.lease_scanner?.fresh === false) degraded.push('lease scanner');
  if (result.payload?.invariant_auditor?.fresh === false) degraded.push('auditor');
  if (result.payload?.telemetry?.status && !['READY', 'DISABLED'].includes(result.payload.telemetry.status)) degraded.push('telemetry');
  badge.textContent = `control plane degraded${degraded.length ? ` · ${degraded.join(', ')}` : ''}`;
  badge.classList.add('error');
}

async function loadRuns(signal) {
  const runs = await api('/v1/runs', {}, {signal});
  const select = $('runSelect');
  const previous = state.runId;
  select.innerHTML = runs.length
    ? runs.map(run => `<option value="${escapeHtml(run.id)}">${escapeHtml(run.name)} · ${short(run.id)}</option>`).join('')
    : '<option value="">No runs</option>';
  const previousAvailable = previous && runs.some(run => run.id === previous);
  if (previous && !previousAvailable) clearProtectedState();
  state.runId = previousAvailable ? previous : (runs[0]?.id ?? null);
  select.value = state.runId ?? '';
}

function commandForNode(nodeId) {
  return (state.graph?.commands ?? []).find(command => command.replacement_node_id === nodeId)
    ?? (state.graph?.commands ?? []).find(command => command.target_node_id === nodeId)
    ?? null;
}

function staleActionsForNode(nodeId) {
  return state.actions.filter(action =>
    action.node_id === nodeId
    && action.decision === 'DENY'
    && ['SCOPE_CANCELLED', 'SCOPE_SUPERSEDED', 'SCOPE_VERSION_MISMATCH'].includes(action.denial_reason)
  );
}

function descendantIds(rootId) {
  const children = new Map();
  for (const edge of state.graph?.edges ?? []) {
    if (edge.type !== 'spawn') continue;
    const bucket = children.get(edge.source) ?? [];
    bucket.push(edge.target);
    children.set(edge.source, bucket);
  }
  const found = new Set([rootId]);
  const queue = [rootId];
  while (queue.length) {
    const current = queue.shift();
    for (const child of children.get(current) ?? []) {
      if (!found.has(child)) {
        found.add(child);
        queue.push(child);
      }
    }
  }
  return found;
}

function drawGraphEdges() {
  const canvas = $('graphCanvas');
  const columns = $('graphColumns');
  const svg = $('graphEdges');
  if (!canvas || !columns || !svg || !state.graph) return;

  const width = Math.max(columns.scrollWidth, canvas.clientWidth);
  const height = Math.max(columns.offsetHeight, 120);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.style.width = `${width}px`;
  svg.style.height = `${height}px`;

  const canvasRect = canvas.getBoundingClientRect();
  const paths = [];
  for (const edge of state.graph.edges) {
    const source = canvas.querySelector(`[data-node="${CSS.escape(edge.source)}"]`);
    const target = canvas.querySelector(`[data-node="${CSS.escape(edge.target)}"]`);
    if (!source || !target) continue;
    const from = source.getBoundingClientRect();
    const to = target.getBoundingClientRect();
    const x1 = from.right - canvasRect.left + canvas.scrollLeft;
    const y1 = from.top + from.height / 2 - canvasRect.top;
    const x2 = to.left - canvasRect.left + canvas.scrollLeft;
    const y2 = to.top + to.height / 2 - canvasRect.top;
    const bend = Math.max(28, (x2 - x1) * 0.48);
    const path = `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`;
    paths.push(`<path class="graph-edge ${escapeHtml(edge.type)}" d="${path}" marker-end="url(#arrow-${escapeHtml(edge.type)})"></path>`);
  }
  svg.innerHTML = `
    <defs>
      <marker id="arrow-spawn" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
      <marker id="arrow-supersedes" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker>
    </defs>${paths.join('')}`;
}

function renderGraph() {
  const focusedNode = document.activeElement?.dataset?.node ?? null;
  const graph = state.graph;
  if (!graph) {
    $('graph').innerHTML = '<p class="muted">No graph.</p>';
    return;
  }
  const groups = new Map();
  for (const node of graph.nodes) {
    const bucket = groups.get(node.generation) ?? [];
    bucket.push(node);
    groups.set(node.generation, bucket);
  }
  const generations = [...groups.keys()].sort((a, b) => Number(a) - Number(b));
  const minWidth = Math.max(640, generations.length * 250);
  const latestCommand = graph.commands.at(-1) ?? null;
  const affected = latestCommand ? descendantIds(latestCommand.target_node_id) : new Set();

  $('graph').innerHTML = `
    <div class="graph-legend" aria-label="Graph edge legend">
      <span><i class="legend-line spawn"></i>spawn lineage</span>
      <span><i class="legend-line supersedes"></i>replacement lineage</span>
      ${latestCommand ? `<span class="command-chip">latest ${escapeHtml(latestCommand.type)} · ${short(latestCommand.id)}</span>` : ''}
    </div>
    <div class="graph-canvas" id="graphCanvas">
      <svg id="graphEdges" class="graph-edges" aria-hidden="true"></svg>
      <div class="graph-columns" id="graphColumns" style="min-width:${minWidth}px;grid-template-columns:repeat(${Math.max(generations.length, 1)},minmax(220px,1fr))">
        ${generations.map(generation => `
          <section class="generation-column" aria-label="Generation ${generation}">
            <div class="generation-label">Generation ${generation}</div>
            <div class="generation-nodes">${(groups.get(generation) ?? []).map(node => {
              const staleCount = staleActionsForNode(node.id).length;
              const command = commandForNode(node.id);
              const classes = [
                'node',
                state.selectedNode === node.id ? 'selected' : '',
                affected.has(node.id) ? 'command-affected' : '',
                node.caused_by_command_id ? 'replacement-node' : '',
              ].filter(Boolean).join(' ');
              return `
                <button type="button" class="${classes}" data-node="${escapeHtml(node.id)}" data-status="${escapeHtml(node.effective_status)}">
                  <div class="node-head">
                    <div class="role">${escapeHtml(node.role)}</div>
                    <span class="behavior">${escapeHtml(node.behavior)}</span>
                  </div>
                  <div class="id">${short(node.id)}</div>
                  <div class="statuses">
                    <span class="status ${node.declared_status}">declared ${node.declared_status}</span>
                    <span class="status ${node.effective_status}">effective ${node.effective_status}</span>
                    <span class="status">lease ${escapeHtml(node.lease_state)}</span>
                  </div>
                  <div class="scope-row">
                    <span>scope ${short(node.own_scope_id)}</span>
                    <strong>v${node.own_scope_version} · ${escapeHtml(node.own_scope_status)}</strong>
                  </div>
                  ${node.blocking_reason ? `<div class="block-reason">blocked by ${escapeHtml(node.blocking_reason)} · ${short(node.blocking_scope_id)}</div>` : ''}
                  ${staleCount ? `<div class="blocked-badge">${staleCount} stale action${staleCount === 1 ? '' : 's'} blocked</div>` : ''}
                  ${node.supersedes_node_id ? `<div class="lineage-note">replaces ${short(node.supersedes_node_id)}</div>` : ''}
                  ${command ? `<div class="lineage-note">command ${short(command.id)}</div>` : ''}
                </button>`;
            }).join('')}</div>
          </section>`).join('')}
      </div>
    </div>`;
  document.querySelectorAll('[data-node]').forEach(button => {
    button.addEventListener('click', () => selectNode(button.dataset.node));
  });
  if (focusedNode) {
    document.querySelector(`[data-node="${CSS.escape(focusedNode)}"]`)?.focus();
  }
  requestAnimationFrame(drawGraphEdges);
}

function selectNode(id) {
  state.selectedNode = id;
  const node = state.graph?.nodes.find(item => item.id === id);
  const relatedCommand = node ? commandForNode(node.id) : null;
  const blocked = node ? staleActionsForNode(node.id) : [];
  $('nodeInspector').innerHTML = node ? `
    <strong>${escapeHtml(node.role)}</strong>
    <span class="behavior" style="float:right">${escapeHtml(node.behavior)}</span>
    <div class="muted" style="margin-top:6px">${escapeHtml(node.id)}</div>
    <div style="margin-top:8px">Generation ${node.generation} · instruction v${node.instruction_version} · ${node.inherited_scope_count} inherited scope(s)</div>
    <div style="margin-top:5px">${node.declared_status} → <strong class="${node.effective_status}">${node.effective_status}</strong></div>
    <div class="scope-row" style="margin-top:8px"><span>owned scope ${short(node.own_scope_id)}</span><strong>v${node.own_scope_version} · ${escapeHtml(node.own_scope_status)}</strong></div>
    ${node.blocking_reason ? `<div class="block-reason" style="margin-top:8px">${escapeHtml(node.blocking_reason)} at ${short(node.blocking_scope_id)}</div>` : ''}
    <h3>Capabilities</h3>
    <div class="capabilities">${node.capabilities.length ? node.capabilities.map(value => `<span>${escapeHtml(value)}</span>`).join('') : '<span>none</span>'}</div>
    ${blocked.length ? `<h3>Blocked attempts</h3>${blocked.map(action => `<div class="notice">${escapeHtml(action.tool_name)} · ${escapeHtml(action.denial_reason)}</div>`).join('')}` : ''}
    ${relatedCommand?.replacement_manifest ? `<h3>Authorized replacement manifest</h3><pre class="manifest">${escapeHtml(JSON.stringify(relatedCommand.replacement_manifest, null, 2))}</pre>` : ''}`
    : 'Select a graph node.';
  renderGraph();
}

function renderTimeline() {
  const commands = state.graph?.commands ?? [];
  $('timeline').innerHTML = commands.length ? commands.map(command => `
    <div class="event">
      <strong>${escapeHtml(command.type)} · ${short(command.target_node_id)}</strong>
      <small>${escapeHtml(command.reason_code)} · scope v${command.from_version} → v${command.to_version} · ${new Date(command.created_at).toLocaleTimeString()}</small>
    </div>`).join('') : '<p class="muted">No control commands.</p>';
}

function renderActions() {
  $('actions').innerHTML = state.actions.length ? state.actions.map(action => `
    <tr>
      <td>${new Date(action.attempted_at).toLocaleTimeString()}</td>
      <td>${short(action.node_id)}</td>
      <td>${escapeHtml(action.tool_name)}</td>
      <td class="${action.decision}">${action.decision}</td>
      <td>${escapeHtml(action.denial_reason ?? '—')}</td>
      <td>${action.committed ? 'yes' : 'no'}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="muted">No actions.</td></tr>';
}

function renderServices() {
  $('services').innerHTML = state.services.length ? state.services.map(service => `
    <div class="notice" style="margin-bottom:7px">
      <strong>${escapeHtml(service.service_name)}</strong>
      <span style="float:right" class="${service.status === 'healthy' ? 'VERIFIED' : 'PARTIAL'}">${escapeHtml(service.status)}</span>
      <div class="muted" style="margin-top:5px">restarts ${service.restart_count} · pool resets ${service.pool_reset_count}</div>
    </div>`).join('') : '<p class="muted">Not seeded.</p>';
}

function renderViolations() {
  $('violations').innerHTML = state.violations.length ? state.violations.map(violation => `
    <div class="notice error" style="margin-bottom:7px">
      <strong>${escapeHtml(violation.violation_type ?? 'SAFETY_VIOLATION')}</strong>
      <div class="muted" style="margin-top:5px">${escapeHtml(violation.reason_code ?? violation.details ?? 'Invariant violation recorded')}</div>
      <div class="muted" style="margin-top:4px">action ${short(violation.action_id)} · command ${short(violation.command_id)}</div>
    </div>`).join('') : '<p class="muted">No durable safety violations.</p>';
}

function renderProof() {
  const proof = state.proof;
  if (!proof) {
    $('proof').innerHTML = '<p class="muted">No completed proof loaded.</p>';
    return;
  }
  $('proof').innerHTML = `
    <div class="verdict ${proof.overall_verdict}">${proof.overall_verdict}</div>
    <p class="muted">control ${proof.control_convergence_verdict} · replacement ${proof.replacement_lineage_verdict} · action ${proof.recovery_action_verdict} · postcondition ${proof.recovery_postcondition_verdict} · stability ${proof.recovery_stability_verdict} · telemetry ${proof.telemetry_verdict}</p>
    <div class="proof-grid">
      <div class="proof-item"><span>Affected</span><strong>${proof.affected_registered_nodes}</strong></div>
      <div class="proof-item"><span>Blocked stale</span><strong>${proof.stale_action_attempts}</strong></div>
      <div class="proof-item"><span>Stale committed</span><strong>${proof.stale_actions_committed}</strong></div>
      <div class="proof-item"><span>Sibling impact</span><strong>${proof.unrelated_branches_interrupted}</strong></div>
    </div>
    <h3>Classifications</h3>
    ${Object.entries(proof.classifications).map(([key, value]) => `<div class="notice" style="margin-top:6px">${escapeHtml(key)} <strong style="float:right">${value}</strong></div>`).join('')}
    ${proof.discrepancies.length ? `<h3>Evidence notes</h3>${proof.discrepancies.map(note => `<div class="notice">${escapeHtml(note)}</div>`).join('')}` : ''}`;
}

function renderMetrics() {
  const nodes = state.graph?.nodes ?? [];
  $('mNodes').textContent = nodes.length;
  $('mActive').textContent = nodes.filter(node => node.effective_status === 'ACTIVE').length;
  $('mCommands').textContent = state.graph?.commands?.length ?? 0;
  $('mBlocked').textContent = state.actions.filter(action =>
    action.decision === 'DENY' && ['SCOPE_CANCELLED', 'SCOPE_SUPERSEDED', 'SCOPE_VERSION_MISMATCH'].includes(action.denial_reason)
  ).length;
  $('mCommitted').textContent = state.proof?.stale_actions_committed ?? 0;
}

async function maybeLoadProof(signal, force = false) {
  const command = state.graph?.commands?.at(-1);
  if (!command) {
    state.proof = null;
    state.proofCommandId = null;
    return;
  }
  const now = Date.now();
  if (!force && state.proofCommandId === command.id && now - state.proofFetchedAt < 3000) return;
  state.proof = await api(`/v1/commands/${command.id}/proof`, {}, {signal});
  state.proofCommandId = command.id;
  state.proofFetchedAt = now;
}

async function refresh({forceProof = false, supersede = false} = {}) {
  if (state.refreshInFlight && !supersede) return;
  if (supersede && state.refreshController) state.refreshController.abort();
  state.refreshInFlight = true;
  const sequence = ++state.refreshSequence;
  const controller = new AbortController();
  state.refreshController = controller;
  try {
    await api('/livez', {}, {auth: false, signal: controller.signal});
    renderHealth(await readiness(controller.signal));
    await loadRuns(controller.signal);
    if (sequence !== state.refreshSequence) return;
    if (!state.runId) {
      state.graph = null; state.actions = []; state.services = []; state.violations = []; state.proof = null;
    } else {
      const runId = state.runId;
      const [graph, actions, services, violations] = await Promise.all([
        api(`/v1/runs/${runId}/graph`, {}, {signal: controller.signal}),
        api(`/v1/runs/${runId}/actions`, {}, {signal: controller.signal}),
        api(`/v1/runs/${runId}/services`, {}, {signal: controller.signal}),
        api(`/v1/runs/${runId}/violations`, {}, {signal: controller.signal}),
      ]);
      if (sequence !== state.refreshSequence || runId !== state.runId) return;
      state.graph = graph;
      state.actions = actions;
      state.services = services;
      state.violations = violations;
      if (state.selectedNode && !graph.nodes.some(node => node.id === state.selectedNode)) {
        state.selectedNode = null;
        $('nodeInspector').textContent = 'Select a graph node.';
      }
      await maybeLoadProof(controller.signal, forceProof);
    }
    renderGraph(); renderTimeline(); renderActions(); renderServices(); renderViolations(); renderProof(); renderMetrics();
  } catch (error) {
    if (error.name !== 'AbortError') {
      $('health').textContent = error.message.includes('operator key') ? 'operator authentication required' : 'control plane unavailable';
      $('health').classList.add('error');
      if (error.status === 401) clearProtectedState();
      console.error(error);
    }
  } finally {
    if (state.refreshController === controller) {
      state.refreshController = null;
      state.refreshInFlight = false;
    }
  }
}

$('operatorKey').addEventListener('input', () => clearProtectedState());
$('operatorKey').addEventListener('change', () => refresh({forceProof: true, supersede: true}));
$('runSelect').addEventListener('change', event => {
  clearProtectedState();
  state.runId = event.target.value || null;
  refresh({forceProof: true, supersede: true});
});
$('refreshBtn').addEventListener('click', () => refresh({forceProof: true, supersede: true}));
$('commandBtn').addEventListener('click', async () => {
  if (state.commandSubmitting) return;
  if (!state.selectedNode) {
    $('commandFeedback').textContent = 'Select a target node first.';
    return;
  }
  state.commandSubmitting = true;
  $('commandBtn').disabled = true;
  try {
    const isCorrection = $('commandType').value === 'CORRECT_SUBTREE';
    const replacementInstruction = isCorrection ? JSON.parse($('replacement').value) : null;
    const expectedTool = isCorrection ? $('replacementTool').value.trim() || null : null;
    const selected = state.graph?.nodes.find(node => node.id === state.selectedNode);
    const affectedCount = descendantIds(state.selectedNode).size;
    const confirmation = `${$('commandType').value} on ${selected?.role ?? short(state.selectedNode)}.\nEstimated immediate scope: ${affectedCount} registered node(s).\nReason: ${$('reasonText').value}`;
    if (!window.confirm(confirmation)) return;
    const result = await api('/v1/commands', {
      method: 'POST',
      body: JSON.stringify({
        idempotency_key: `ui-${state.runId}-${crypto.randomUUID()}`,
        command_type: $('commandType').value,
        target_node_id: state.selectedNode,
        reason_code: $('reasonCode').value,
        reason_text: $('reasonText').value,
        replacement_instruction: replacementInstruction,
        replacement_expected_tool: expectedTool,
        recovery_stability_seconds: isCorrection
          ? Number.parseInt($("recoveryStability").value, 10) || 0
          : 0,
      }),
    });
    const manifestSummary = result.replacement_manifest
      ? ` Replacement: ${result.replacement_manifest.role}, ${result.replacement_manifest.capabilities_exact.join(', ') || 'no tools'}.`
      : '';
    $('commandFeedback').textContent = `Issued ${short(result.command_id)}.${manifestSummary}`;
    state.proof = null;
    await refresh({forceProof: true});
  } catch (error) {
    $('commandFeedback').textContent = error.message;
  } finally {
    state.commandSubmitting = false;
    $('commandBtn').disabled = false;
  }
});

setInterval(() => {
  if ($('autoRefresh').value === 'on') refresh();
}, 2000);

api('/livez', {}, {auth: false})
  .then(() => readiness())
  .then(result => { renderHealth(result); })
  .catch(() => { $('health').textContent = 'control plane unavailable'; $('health').classList.add('error'); });

let graphResizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(graphResizeTimer);
  graphResizeTimer = setTimeout(drawGraphEdges, 80);
});
