import * as dotenv from 'dotenv';
dotenv.config();
process.env.NODE_ENV = 'testing';
import {expect} from 'chai';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import 'cross-fetch/polyfill';
import {google} from 'googleapis';
import * as jwt from 'jsonwebtoken';
import 'mocha';
import {jwtBearerVerify, jwtDeleteKid, jwtVerify, testGetCache, wasItCached} from '../src';
import {Credentials} from 'google-auth-library';
// tslint:disable: no-unused-expression
chai.use(chaiAsPromised);

let GOOGLE_ID_TOKEN: string;
let AZURE_ACCESS_TOKEN: string;

function azureMultilineEnvFix(input: string | undefined) {
	if (input === undefined) {
		return undefined;
	}
	return input.replace(/\\n/g, '\n');
}

function getAccessToken(): Promise<string> {
	console.log('getAccessToken');
	const clientKey = azureMultilineEnvFix(process.env.GOOGLE_CLIENT_KEY);
	console.log(clientKey);
	return new Promise((resolve, reject) => {
		const jwtClient = new google.auth.JWT(
			process.env.GOOGLE_CLIENT_EMAIL,
			undefined,
			clientKey,
			['openid', 'https://www.googleapis.com/auth/cloud-platform'],
			undefined,
		);
		jwtClient.authorize((err: Error, cred: Credentials) => {
			if (err) {
				reject(err);
				return;
			}
			if (!cred || !cred.access_token) {
				reject(new Error('no access token'));
			} else {
				resolve(cred.access_token);
			}
		});
	});
}

const getGoogleIdToken = async () => {
	console.log('getGoogleIdToken');
	const body = JSON.stringify({
		audience: process.env.GOOGLE_CLIENT_EMAIL,
		delegates: [],
		includeEmail: true,
	});
	const headers = new Headers();
	headers.set('Authorization', 'Bearer ' + (await getAccessToken()));
	headers.set('Content-Type', 'application/json');
	headers.set('Content-Length', '' + body.length);
	console.log('getGoogleIdToken fetch');
	const res = await fetch(`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${process.env.GOOGLE_CLIENT_EMAIL}:generateIdToken`, {
		body,
		headers,
		method: 'POST',
	});
	if (res.status !== 200) {
		throw new Error('getGoogleIdToken code ' + res.status);
	}
	const data = await res.json();
	return data.token;
};

const getAzureAccessToken = async () => {
	console.log('getAzureAccessToken');
	// NOTE: Azure v2.0 accessToken is not atm valid JWT token (https://github.com/microsoft/azure-spring-boot/issues/476)
	const body = `client_id=${process.env.AZ_CLIENT_ID}&client_secret=${process.env.AZ_CLIENT_SECRET}&grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default`;
	const headers = new Headers();
	headers.set('Content-Type', 'application/x-www-form-urlencoded');
	headers.set('Content-Length', '' + body.length);
	console.log('getAzureAccessToken fetch');
	const res = await fetch(`https://login.microsoftonline.com/${process.env.AZ_TENANT_ID}/oauth2/token`, {method: 'POST', headers, body});
	if (res.status !== 200) {
		throw new Error('getAzureAccessToken code ' + res.status);
	}
	const data = await res.json();
	return data.access_token;
};

describe('jwtUtil', () => {
	before(async function () {
		this.timeout(30000);
		AZURE_ACCESS_TOKEN = await getAzureAccessToken();
		GOOGLE_ID_TOKEN = await getGoogleIdToken();
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
		const decode = await jwtVerify(AZURE_ACCESS_TOKEN);
		expect(decode).not.to.be.null;
	});
});
