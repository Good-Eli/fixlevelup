// Do not forward Playwright request/response, locator, console, or app output.
export default class LiveReporter {
  onTestEnd(_test, result) {
    const line = result.errors[0]?.stack?.match(/p0404-live\.spec\.ts:(\d{1,5}):\d+/)?.[1];
    console.log(`P04-04 HTTPS browser: ${result.status}${result.status === 'passed' ? '' : ` (fixture line ${line ?? 'unknown'})`}`);
  }
  onError() { console.error('P04-04 HTTPS browser runner failed (private details suppressed)'); }
  printsToStdio() { return true; }
}
