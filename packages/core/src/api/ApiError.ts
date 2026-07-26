export interface ApiError extends Error {
  errorCode: string;
  statusCode: number;
}

export function isApiError(err: unknown): err is ApiError {
  return (
    err instanceof Error &&
    'errorCode' in err && typeof (err as any).errorCode === 'string' &&
    'statusCode' in err && typeof (err as any).statusCode === 'number'
  );
}
