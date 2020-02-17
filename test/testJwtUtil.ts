process.env.NODE_ENV = 'testing';
import {expect} from 'chai';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as jwt from 'jsonwebtoken';
import 'mocha';
import {jwtBearerVerify, jwtDeleteKid, jwtVerify, testGetCache, wasItCached} from '../src';
chai.use(chaiAsPromised);

let GOOGLE_ID_TOKEN: string;

describe('jwtUtil', () => {
	before(() => {
		if (!process.env.GOOGLE_ID_TOKEN) {
			throw new Error('missing GOOGLE_ID_TOKEN env');
		}
		GOOGLE_ID_TOKEN = process.env.GOOGLE_ID_TOKEN;
	});
	it('Test expire cache', () => {
		const cache = testGetCache();
		cache.put('test', {none: 'test'}, 0);
		expect(cache.getCacheSize()).to.be.eq(1);
		expect(cache.get('test')).to.be.eq(undefined); // shoud remove test as it's expired
		expect(cache.getCacheSize()).to.be.eq(0);
	});
	it('Test Google IdToken', async () => {
		const decode = await jwtVerify(GOOGLE_ID_TOKEN as string);
		expect(decode).not.to.be.null;
		expect(wasItCached()).to.be.eq(false);
	});
	it('Test Google IdToken cached', async () => {
		const decode = await jwtVerify(GOOGLE_ID_TOKEN as string);
		expect(decode).not.to.be.null;
		expect(wasItCached()).to.be.eq(true);
	});
	it('Test Google token as Bearer Token', async () => {
		const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
		expect(decode).not.to.be.null;
	});
	it('Test non Bearer auth', async () => {
		try {
			await jwtBearerVerify('Basic some:fun');
			throw new Error("should not happen as we don't have parameters");
		} catch (err) {
			// ok
		}
	});
	it('Test non issuer token ', async () => {
		const test = jwt.sign({test: 'asd'}, 'secret');
		try {
			await jwtVerify(test);
			throw new Error("should not happen as we don't have parameters");
		} catch (err) {
			// ok
		}
	});
	it('Test non-valid issuer', async () => {
		try {
			await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['not_valid_issuer']});
			throw new Error("should not happen as we don't have parameters");
		} catch (err) {
			// ok
		}
	});
	it('Test delete kid and check force reload', async () => {
		const decoded = jwt.decode(GOOGLE_ID_TOKEN, {complete: true}) as any;
		jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
		const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
		expect(decode).not.to.be.null;
	});
	it('test Azure ID Token ', async () => {
		const decode = await jwtVerify(process.env.AZURE_ID_TOKEN as string);
		expect(decode).not.to.be.null;
	});
});
