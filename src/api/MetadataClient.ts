// Reads Metadata API components (e.g. SecuritySettings) that are not exposed as
// SOQL/Tooling objects. Returns null when the component is absent or unreadable,
// so callers degrade to an advisory rather than crashing.
export interface MetadataClient {
  read<T = Record<string, unknown>>(type: string, fullName: string): Promise<T | null>;
}
