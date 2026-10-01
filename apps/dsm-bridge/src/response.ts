/** Preserve a bounded management error when DSM replaces HTTP 5xx bodies with HTML.
 * This applies only to the DSM CGI transport, never to MCP or OAuth endpoints.
 * Consumers must reject `error` even when the transport status is 200.
 */
export function cgiResponse(result: {status:number;body:unknown}) {
  if (result.status < 500) return result;
  const error = result.body && typeof result.body === 'object' && 'error' in result.body
    ? result.body.error : undefined;
  return {status:200,body:{error:typeof error === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error)
    ? error : 'DSM_BRIDGE_UNAVAILABLE',httpStatus:result.status}};
}
