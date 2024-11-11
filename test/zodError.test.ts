/* eslint-disable sort-imports, import/first, no-unused-expressions, sonarjs/no-duplicate-string */
process.env.NODE_ENV = 'testing';
import {describe, expect, it} from 'vitest';
import {formatZodError} from '../src/lib/zodUtils';
import {openIdConfigSchema} from '../src/interfaces/OpenIdConfig';

describe('zodUtils', () => {
	describe('formatZodError', () => {
		it('should build simple error with string from Zod Error', () => {
			let error: Error | undefined;
			const result = openIdConfigSchema.safeParse({});
			expect(result.success).to.be.eq(false);
			if (!result.success) {
				error = formatZodError(result.error);
				expect(error?.message).to.be.equal('issuer: Required, jwks_uri: Required');
			} else {
				throw new Error('Zod validation should fail');
			}
		});
	});
});
