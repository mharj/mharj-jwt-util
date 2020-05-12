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
import {jwtBearerVerify, jwtDeleteKid, jwtVerify, testGetCache, wasItCached, jwtVerifyPromise, jwtHaveIssuer} from '../src';
import {Credentials} from 'google-auth-library';
import {IssuerCertLoader} from '../src/issuerCertLoader';
import {buildCertFrame} from '../src/rsaPublicKeyPem';
// tslint:disable: no-unused-expression
chai.use(chaiAsPromised);

let GOOGLE_ID_TOKEN: string;
let AZURE_ACCESS_TOKEN: string;
let icl: IssuerCertLoader;

function azureMultilineEnvFix(input: string | undefined) {
	if (input === undefined) {
		return undefined;
	}
	return input.replace(/\\n/g, '\n');
}

function getAccessToken(): Promise<string> {
	const clientKey = azureMultilineEnvFix(process.env.GOOGLE_CLIENT_KEY);
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
	const body = JSON.stringify({
		audience: process.env.GOOGLE_CLIENT_EMAIL,
		delegates: [],
		includeEmail: true,
	});
	const headers = new Headers();
	headers.set('Authorization', 'Bearer ' + (await getAccessToken()));
	headers.set('Content-Type', 'application/json');
	headers.set('Content-Length', '' + body.length);
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
	// NOTE: Azure v2.0 accessToken is not atm valid JWT token (https://github.com/microsoft/azure-spring-boot/issues/476)
	const body = `client_id=${process.env.AZ_CLIENT_ID}&client_secret=${process.env.AZ_CLIENT_SECRET}&grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default`;
	const headers = new Headers();
	headers.set('Content-Type', 'application/x-www-form-urlencoded');
	headers.set('Content-Length', '' + body.length);
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
	describe('jwtVerifyPromise', () => {
		it('should fail internal jwtVerifyPromise with broken data', async () => {
			expect(jwtVerifyPromise('qwe', 'qwe')).to.be.rejectedWith('jwt malformed');
		});
	});
	describe('jwtVerify', () => {
		it('should fail if brokwn token', async () => {
			expect(jwtVerify('asd')).to.be.rejectedWith("Can't decode token");
		});
		it('should fail is issuer url is missing', async () => {
			const test = jwt.sign({}, 'test');
			expect(jwtVerify(test)).to.be.rejectedWith('token missing required parameters');
		});
		it('should fail is kid is missing', async () => {
			const test = jwt.sign({}, 'test', {issuer: 'https://accounts.google.com'});
			expect(jwtVerify(test)).to.be.rejectedWith('token header missing required parameters');
		});
	});
	describe('cache', () => {
		it('Test expire cache', () => {
			const cache = testGetCache();
			cache.put('test', {none: 'test'}, 0);
			expect(cache.getCacheSize()).to.be.eq(1);
			expect(cache.get('test')).to.be.eq(undefined); // shoud remove test as it's expired
			expect(cache.getCacheSize()).to.be.eq(0);
		});
	});
	describe('tokens', () => {
		it('Test Google IdToken', async () => {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const decode = await jwtVerify(GOOGLE_ID_TOKEN as string);
			expect(decode).not.to.be.null;
			expect(wasItCached()).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
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
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.null;
		});
		it('test Azure ID Token ', async () => {
			const decode = await jwtVerify(AZURE_ACCESS_TOKEN);
			expect(decode).not.to.be.null;
		});
	});
	describe('test IssuerCertLoader', () => {
		before(async () => {
			icl = new IssuerCertLoader();
		});
		it('should throw if issuer is not found', async () => {
			await expect(icl.getCert('https://123qweasdqwe123zzz', 'unknown')).to.be.rejected;
		});
		it('should throw when get cert for unknown kid ', async () => {
			await expect(icl.getCert('https://accounts.google.com', 'unknown')).to.be.rejectedWith('something strange - still no cert found for issuer!');
		});
	});
	describe('test buildCertFrame', () => {
		it('should get RSA PUBLIC key structure as Buffer', async () => {
			const data = Buffer.from(
				'MIIBCgKCAQEA18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf//7pVEVJJyDuL5a8PARRYQtH68w+0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M/8pJ6qiOjvjF9bhEq0CC/f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9/NdCUuCsdqavd4T+VWnbplbB8YsC+R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE+nCIDwIDAQAB',
			);
			expect(buildCertFrame(data)).to.be.a.instanceof(Buffer);
		});
		it('should fail if not correct Buffer', async () => {
			expect(buildCertFrame.bind(null, Buffer.from(''))).to.be.throw('Cert data error');
		});
		it('should get secret key as string', async () => {
			const data = 'secretKey';
			expect(buildCertFrame(data)).to.be.a('string');
		});
	});
});
