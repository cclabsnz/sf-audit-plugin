export interface RestClient {
  // path is relative to /services/data/vXX.0/ e.g. '/limits' or '/sobjects/Account/describe/'
  get<T>(path: string): Promise<T>;
  // Like get, but returns the response body verbatim as a string. Use for endpoints that
  // return non-JSON payloads — e.g. EventLogFile's /LogFile, which returns text/csv.
  // NOTE: buffers the whole body in memory; do not use for large LogFiles (see getRawToFile).
  getRaw(path: string): Promise<string>;
  // Stream a non-JSON body straight to a file, never holding it in memory. Required for large
  // EventLogFile LogFiles (a busy org's daily Sites/URI logs can be hundreds of MB and exceed
  // the max JS string length). Returns the number of bytes written.
  getRawToFile(path: string, destPath: string): Promise<number>;
}
