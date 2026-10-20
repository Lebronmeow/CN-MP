'use strict';

// Standalone regression checks: node tests-v4.js (no dependencies).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const api = require('./script.js');

assert.equal(api.defaultRules.length, 6);
assert.ok(Object.isFrozen(api.defaultRules));
assert.ok(api.defaultRules.every(Object.isFrozen));
assert.ok(api.changeRule(2, 'ALLOW'));
let edited = api.getRules();
assert.equal(api.defaultRules[2].decision, 'DENY');
assert.match(api.ruleReason(edited[2], 2), /User override: ALLOW.*Security risk.*segmentation/);
assert.doesNotMatch(api.ruleReason(edited[2], 2), /never exposed/);
assert.ok(api.changeRule(4, 'ALLOW'));
assert.match(api.ruleReason(api.getRules()[4], 4), /database bypasses the application tier/);
assert.ok(api.changeRule(1, 'ALLOW'));
assert.match(api.ruleReason(api.getRules()[1], 1), /bypasses the web tier/);
assert.ok(api.changeRule(0, 'DENY'));
assert.match(api.ruleReason(api.getRules()[0], 0), /service.*stops working/);
assert.equal(api.changeRule(0, 'DROP'), false);
assert.equal(api.changeRule(9, 'ALLOW'), false);
edited[0].decision = 'ALLOW';
assert.equal(api.getRules()[0].decision, 'DENY', 'external snapshots cannot mutate policy');
api.resetRules();
assert.deepEqual(api.getRules(), api.defaultRules);
assert.equal(api.ruleReason(api.getRules()[2], 2), api.defaultRules[2].why);

api.resetLearning();
assert.equal(api.gradeExercise(0, 1).correct, false);
assert.equal(api.gradeExercise(0, 0).progress, 1);
assert.equal(api.gradeExercise(0, 0).progress, 1, 'repeat answers earn no duplicate credit');
api.changeRule(2, 'ALLOW');
assert.equal(api.gradeExercise(1, 0).correct, false, 'quiz remains baseline-based after edits');
assert.equal(api.gradeExercise(1, 1).progress, 2);
assert.equal(api.gradeExercise(2, 2).progress, 3);
assert.equal(api.gradeExercise(2, 0).progress, 3, 'earned progress is retained');
assert.equal(api.gradeExercise(7, 0), null);
api.resetLearning();
assert.equal(api.gradeExercise(0, 1).progress, 0);
api.resetRules();

assert.equal(api.modeledService('443').service.destination, 'web');
assert.equal(api.modeledService('5000').service.name, 'Application API');
assert.equal(api.modeledService('3306').service.destination, 'database');
assert.deepEqual(api.modeledService('8080'), { valid: true, port: 8080, service: null });
for (const port of ['', '0', '65536', '3.5', '-1', '443<script>']) assert.equal(api.modeledService(port).valid, false);
assert.deepEqual(api.transportSnapshot(0).tcp, []);
assert.equal(api.transportSnapshot(2).dropped, true);
assert.deepEqual(api.transportSnapshot(3).tcp, [1]);
assert.deepEqual(api.transportSnapshot(3).buffered, [3], 'TCP holds piece 3 for ordered delivery');
assert.deepEqual(api.transportSnapshot(4).tcp, [1, 2, 3]);
assert.deepEqual(api.transportSnapshot(4).udp, [1, 3], 'UDP never repairs the illustrative gap');
assert.equal(api.transportSnapshot(4).resent, true);
assert.deepEqual([1, 2, 3].map(api.tierRequest), [
  { source: 'client', destination: 'web', port: 443 },
  { source: 'web', destination: 'app', port: 5000 },
  { source: 'app', destination: 'database', port: 3306 }
]);
assert.equal(api.tierRequest(0), null);
assert.equal(api.tierRequest(4), null);

class Element {
  constructor() { this.dataset = {}; this.style = {}; this.listeners = {}; this.children = []; this.attributes = {}; this.value = ''; this.classList = { toggle() {} }; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  append(...items) { this.children.push(...items); }
  appendChild(item) { this.children = this.children.filter(child => child !== item); this.append(item); }
  replaceChildren(...items) { this.children = items; }
  querySelector() { return null; }
  closest() { return null; }
  focus() { this.focused = true; }
}
const elements = new Map();
const get = id => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
const table = new Element();
table.querySelector = () => table.children.find(child => 'data-rule-caption' in child.attributes) || null;
get('rulesTable').closest = () => table;
const context = vm.createContext({
  document: { getElementById: get, createElement: () => new Element(), querySelector: () => null, querySelectorAll: () => [] },
  window: { matchMedia: () => ({ matches: true }), addEventListener() {} },
  location: { hash: '#learn' }, setTimeout, clearTimeout, console
});
vm.runInContext(fs.readFileSync(require.resolve('./script.js'), 'utf8'), context);
const evaluate = source => vm.runInContext(source, context);
evaluate('renderRules(); renderRules()');
assert.equal(table.children.length, 1);
assert.equal(new Set(table.children).size, 1, 'rerenders reuse the same caption');
assert.equal((get('learnGrid').innerHTML.match(/<details class="learn-card">/g) || []).length, 6);
assert.match(get('learningLab').innerHTML, /aria-pressed="false"/);
assert.match(get('rulesStatus').textContent, /no real firewall changes.*recommended baseline/);
assert.equal((get('rulesTable').innerHTML.match(/class="rule-decision/g) || []).length, 6);
const lab = get('learningLab');
function clickLab(selector, dataset = {}) {
  const target = { dataset, closest: requested => requested === selector ? target : null };
  lab.listeners.click({ target, preventDefault() {} });
}
clickLab('.exercise-option', { exercise: '0', answer: '1' });
assert.match(lab.innerHTML, /is-incorrect/);
assert.match(lab.innerHTML, /Not quite — try again/);
clickLab('.exercise-option', { exercise: '0', answer: '0' });
assert.match(lab.innerHTML, /is-correct/);
assert.match(lab.innerHTML, /1 \/ 3 correct/);
clickLab('.exercise-reset');
assert.doesNotMatch(lab.innerHTML, /is-correct|is-incorrect/);
assert.match(lab.innerHTML, /0 \/ 3 correct/);

const workbench = get('lessonWorkbench');
assert.equal((workbench.innerHTML.match(/data-lesson-tab=/g) || []).length, 4);
assert.match(workbench.innerHTML, /lesson-tab-0"[^>]*aria-pressed="true"/);
assert.match(workbench.innerHTML, /Source IP.*192\.168\.1\.20.*Destination IP.*10\.0\.1\.10/);
function changeLesson(id, value) { workbench.listeners.change({ target: { id, value } }); }
changeLesson('lesson-destination', 'database');
assert.match(workbench.innerHTML, /Addressed to Database Server at 10\.0\.3\.10/);
assert.match(workbench.innerHTML, /data-selected="true".*DATABASE/);
evaluate('selectLesson(1)');
changeLesson('lesson-service', '5000');
assert.match(workbench.innerHTML, /Application API → Application Server :5000/);
changeLesson('lesson-port', '8080');
assert.match(workbench.innerHTML, /no modeled service/);
assert.match(workbench.innerHTML, /Destination IP.*Not modeled/);
evaluate('selectLesson(3)');
workbench.listeners.click({ target: { id: 'lesson-step', closest: () => null } });
assert.match(workbench.innerHTML, /NEW request 1: Client → Web Server :443/);
workbench.listeners.click({ target: { id: 'lesson-step', closest: () => null } });
assert.match(workbench.innerHTML, /Source IP.*10\.0\.1\.10.*Destination IP.*10\.0\.2\.10/);
workbench.listeners.click({ target: { id: 'lesson-restart', closest: () => null } });
assert.match(workbench.innerHTML, /0 \/ 3 separate requests/);
const lessonCallbacks = new Map();
let timerId = 0;
context.setTimeout = callback => { lessonCallbacks.set(++timerId, callback); return timerId; };
context.clearTimeout = id => lessonCallbacks.delete(id);
evaluate('selectLesson(2); startLessonSequence()');
const staleLessonCallback = lessonCallbacks.get(evaluate('lessonTimer'));
evaluate('selectLesson(0)');
assert.equal(evaluate('lessonTimer'), null, 'tab changes clear the playing timer');
assert.equal(evaluate('lessonState.transport'), 0);
assert.equal(evaluate('lessonState.running'), false);
assert.equal(lessonCallbacks.size, 0);
staleLessonCallback();
assert.equal(evaluate('lessonState.transport'), 0, 'even an already queued stale callback cannot update the new tab');
evaluate('selectLesson(2); startLessonSequence()');
const priorReplay = lessonCallbacks.get(evaluate('lessonTimer'));
evaluate('startLessonSequence()');
priorReplay();
assert.equal(evaluate('lessonState.transport'), 0, 'replay invalidates prior callbacks');
for (let stage = 1; stage <= 4; stage++) {
  const id = evaluate('lessonTimer');
  const callback = lessonCallbacks.get(id);
  lessonCallbacks.delete(id);
  callback();
  assert.equal(evaluate('lessonState.transport'), stage);
}
assert.equal(evaluate('lessonState.running'), false);
assert.equal(evaluate('lessonTimer'), null);
assert.match(workbench.innerHTML, /TCP resends piece 2.*UDP does not retransmit/);
assert.match(workbench.innerHTML, /Received: 1, 2, 3/);
assert.match(workbench.innerHTML, /Received: 1, 3/);
context.setTimeout = setTimeout;
context.clearTimeout = clearTimeout;

async function checkRun() {
  get('sourceSelect').value = 'client';
  get('destinationSelect').value = 'database';
  get('portSelect').value = '3306';
  get('protocolSelect').value = 'UDP';
  evaluate("changeRule(2, 'ALLOW')");
  const pending = evaluate('startSimulation()');
  await Promise.resolve();
  assert.equal(evaluate('activeRun.policy[2].decision'), 'ALLOW', 'run uses edited rules');
  evaluate("changeRule(2, 'DENY')");
  assert.equal(evaluate('activeRun.policy[2].decision'), 'ALLOW', 'run owns a separate snapshot');
  const select = { dataset: { ruleIndex: '2' }, value: 'ALLOW', closest() { return this; } };
  get('rulesTable').listeners.change({ target: select });
  await pending;
  assert.equal(evaluate('activeRun'), null);
  assert.equal(get('decisionBadge').textContent, 'POLICY CHANGED');
  assert.equal(get('traceList').children.length, 0, 'no stale trace after policy edit');
  assert.match(get('rulesTable').innerHTML, /data-modified="true"/);
  get('resetRules').listeners.click();
  assert.equal(evaluate('rules[2].decision'), 'DENY');
  assert.equal(get('traceList').children.length, 0);
  assert.match(get('resultTitle').textContent, /run again/);
  console.log('tests-v4: policy editing, reset, explanations, snapshot/cancellation, rendering, quiz grading and hands-on lessons passed');
}
checkRun().catch(error => { console.error(error); process.exitCode = 1; });
