process.env.NODE_ENV = 'testing';
import {expect} from 'chai';
import * as chai from 'chai';
import * as chaiAsPromised from "chai-as-promised";
import * as jwt from 'jsonwebtoken';
import {describe, it} from 'mocha';
import {jwtBearerVerify, jwtVerify} from '../src';
chai.use(chaiAsPromised);

let GOOGLE_ID_TOKEN:string;

describe('jwtUtil', () => {
	before(()=> {
		if (!process.env.GOOGLE_ID_TOKEN) {
			throw new Error('missing GOOGLE_ID_TOKEN env');
		}
		GOOGLE_ID_TOKEN = process.env.GOOGLE_ID_TOKEN;
	});
	it('Test Google IdToken', async () => {
		const decode = await jwtVerify(GOOGLE_ID_TOKEN as string);
		expect(decode).not.to.be.null;
	});
	it('Test Google token as Bearer Token', async () => {
		const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN,['https://accounts.google.com']);
		expect(decode).not.to.be.null;
	});
	it('Test non Bearer auth', async () => {
		try {
			await await jwtBearerVerify('Basic some:fun')
			throw new Error('should not happen as we don\'t have parameters');
		} catch(err) {
			// ok
		}
	});
	it('Test non issuer token ', async() => {
		const test = jwt.sign({test: 'asd'}, 'secret');
		try {
			await jwtVerify(test);
			throw new Error('should not happen as we don\'t have parameters');
		} catch(err) {
			// ok
		}
	});
	it('Test non-valid issuer', async() => {
		try {
			await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN,['not_valid_issuer']);
			throw new Error('should not happen as we don\'t have parameters');
		} catch(err) {
			// ok
		}
	});
});
