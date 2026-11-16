/** Synthetic-only provider adapter; tests of the transport use the production pinnedFetch directly. */
export {
  parseDnsAnswers,
  parseHttpResponse,
} from "../src/security/pinned-fetch";

export async function pinnedFetch(
  url: string,
  init: RequestInit,
): Promise<Response> {
  return fetch(url, init);
}
