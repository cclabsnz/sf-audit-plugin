export interface RestClient {
  // path is relative to /services/data/vXX.0/ e.g. '/limits' or '/sobjects/Account/describe/'
  get<T>(path: string): Promise<T>;
  // Like get, but returns the response body verbatim as a string. Use for endpoints that
  // return non-JSON payloads — e.g. EventLogFile's /LogFile, which returns text/csv.
  getRaw(path: string): Promise<string>;
}
