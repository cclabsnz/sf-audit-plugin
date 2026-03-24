import { isApiError } from '../../../src/api/ApiError.js';

describe('isApiError', () => {
  it('returns true for an object with errorCode (string) and statusCode (number)', () => {
    const err = Object.assign(new Error('API error'), { errorCode: 'INVALID_TYPE', statusCode: 400 });
    expect(isApiError(err)).toBe(true);
  });

  it('returns false for a plain Error with no extra fields', () => {
    expect(isApiError(new Error('plain'))).toBe(false);
  });

  it('returns false when errorCode is missing', () => {
    const err = Object.assign(new Error('x'), { statusCode: 400 });
    expect(isApiError(err)).toBe(false);
  });

  it('returns false when statusCode is missing', () => {
    const err = Object.assign(new Error('x'), { errorCode: 'INVALID' });
    expect(isApiError(err)).toBe(false);
  });

  it('returns false for non-Error values', () => {
    expect(isApiError(null)).toBe(false);
    expect(isApiError('string')).toBe(false);
    expect(isApiError({ errorCode: 'X', statusCode: 400 })).toBe(false);
  });
});
