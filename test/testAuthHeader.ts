process.env.NODE_ENV = 'testing';
import {expect} from 'chai';
import 'mocha';
import {AuthHeader, getAuthType, isAuthType} from '../src/AuthHeader';

describe('AuthHeader', () => {
	describe('fromString', () => {
		it('should have valid auth header', async () => {
			const basic = AuthHeader.fromString('Basic 233123123123123');
			expect(basic.type).to.be.eq('BASIC');
			expect(basic.credentials).to.be.eq('233123123123123');
			expect(basic.toString()).to.be.eq('Basic 233123123123123');
		});
		it('should fail to create unknown auth header', async () => {
			expect(AuthHeader.fromString.bind(undefined, 'XX-YY-ZZ 233123123123123')).to.throw('XX-YY-ZZ is not valid auth header type');
		});
	});
	describe('isAuthHeader', () => {
		it('should validate header types', async () => {
			expect(AuthHeader.isAuthHeader(undefined)).to.be.eq(false);
			expect(AuthHeader.isAuthHeader(null)).to.be.eq(false);
			expect(AuthHeader.isAuthHeader(true)).to.be.eq(false);
			expect(AuthHeader.isAuthHeader({})).to.be.eq(false);
			expect(AuthHeader.isAuthHeader(123)).to.be.eq(false);
			expect(AuthHeader.isAuthHeader('123123123123123')).to.be.eq(false);
			expect(AuthHeader.isAuthHeader('BeArEr 123123123123123')).to.be.eq(true);
		});
	});
	describe('isAuthType', () => {
		it('should validate types', async () => {
			expect(isAuthType(undefined)).to.be.eq(false);
			expect(isAuthType(null)).to.be.eq(false);
			expect(isAuthType(true)).to.be.eq(false);
			expect(isAuthType({})).to.be.eq(false);
			expect(isAuthType(123)).to.be.eq(false);
			expect(isAuthType('123123123123123')).to.be.eq(false);
			expect(isAuthType('BeArEr')).to.be.eq(true);
		});
	});
	describe('getAuthType', () => {
		it('should fail to get auth type', async () => {
			expect(getAuthType.bind(undefined, undefined)).to.throw('undefined is not valid auth header type');
			expect(getAuthType.bind(undefined, null)).to.throw('null is not valid auth header type');
			expect(getAuthType.bind(undefined, true)).to.throw('true is not valid auth header type');
			expect(getAuthType.bind(undefined, {})).to.throw('[object Object] is not valid auth header type');
			expect(getAuthType.bind(undefined, 123)).to.throw('123 is not valid auth header type');
			expect(getAuthType.bind(undefined, '123123123123123')).to.throw('123123123123123 is not valid auth header type');
		});
		it('should get auth type', async () => {
			expect(getAuthType('BeArEr')).to.be.eq('BEARER');
		});
	});
});
