export interface RestClient {
  // path is relative to /services/data/vXX.0/ e.g. '/limits' or '/sobjects/Account/describe/'
  get<T>(path: string): Promise<T>;
}
