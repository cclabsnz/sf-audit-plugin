/**
 * An error's Salesforce code, HTTP status and message as one string, for classifiers that match
 * on text. sf-core 0.12 keeps the code out of the message (`INVALID_SESSION_ID` arrives as
 * "Session expired or invalid"), and an error body with no Salesforce code is
 * `ERROR_HTTP_<status>` with no status on the Connection path; both read here as "HTTP <status>".
 */
export function apiErrorText(e: unknown): string {
  if (!(e instanceof Error)) return String(e);
  const { errorCode, statusCode } = e as { errorCode?: unknown; statusCode?: unknown };
  const code = typeof errorCode === 'string' ? errorCode : '';
  const status = typeof statusCode === 'number' ? statusCode : /^ERROR_HTTP_(\d{3})$/.exec(code)?.[1];
  return [code, status === undefined ? '' : `HTTP ${status}`, e.message].filter(Boolean).join(' ');
}
