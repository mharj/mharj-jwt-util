/* eslint-disable sort-imports, import/first, no-unused-expressions, sonarjs/no-duplicate-string */
process.env.NODE_ENV = 'testing';
import 'mocha';
import * as chai from 'chai';
import {formatZodError} from '../src/lib/zodUtils';
import {openIdConfigSchema} from '../src/interfaces/OpenIdConfig';

const expect = chai.expect;

describe('zodUtils', () => {
	describe('formatZodError', () => {
		it('should build simple error with string from Zod Error', () => {
			let error: Error | undefined;
			try {
				openIdConfigSchema.parse({});
			} catch (e) {
				error = formatZodError(e);
			}
			expect(error?.message).to.be.equal('issuer: Required, jwks_uri: Required');
		});
	});
});
