// Do not forward Playwright locator logs, request/response values, or app output.
export default class LiveReporter {
  onTestEnd(test, result) {
    const failure = result.steps.filter(step => step.category === 'test.step' && step.error).at(-1);
    const stage = failure && ['admin login and cookie', 'CRM legal form publication', 'PostgreSQL publication evidence',
      'manager login and direct authorization', 'PostgreSQL denied-write isolation'].includes(failure.title) ? failure.title : 'setup or teardown';
    const line = result.errors[0]?.stack?.match(/p0305-live\.spec\.ts:(\d+):\d+/)?.[1];
    console.log(`P03-05 HTTPS browser: ${result.status}${result.status === 'passed' ? '' : ` (${stage}; fixture line ${line ?? 'unknown'})`}`);
  }
  onError() { console.error('P03-05 HTTPS browser runner failed (private details suppressed)'); }
  printsToStdio() { return true; }
}
