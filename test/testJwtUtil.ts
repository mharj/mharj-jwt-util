/* eslint-disable sort-imports, import/first, no-unused-expressions, sonarjs/no-duplicate-string */
process.env.NODE_ENV = 'testing';
import 'mocha';
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import dotenv from 'dotenv';
import fs from 'node:fs';
import {sign as jwtSign, decode as jwtDecode, type JwtPayload} from 'jsonwebtoken';
import {type CacheMap, TachyonExpireCache} from 'tachyon-expire-cache';
import {CryptoBufferProcessor, FileStorageDriver} from 'tachyon-drive-node-fs';
import {type IPersistSerializer, MemoryStorageDriver} from 'tachyon-drive';
import {
	buildCertFrame,
	certCacheBufferSerializer,
	certCacheStringSerializer,
	FileCertCache,
	IssuerCertLoader,
	jwtBearerVerify,
	jwtDeleteKid,
	jwtHaveIssuer,
	JwtHeaderError,
	jwtVerify,
	jwtVerifyPromise,
	type RawJwtToken,
	setCertLoader,
	setTokenCache,
	TachyonCertCache,
	testGetCache,
	type TokenPayload,
	useCache,
} from '../src';
import {z} from 'zod';
import {type Credentials} from 'google-auth-library';
import {google} from 'googleapis';

dotenv.config();

const expect = chai.expect;
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

async function getGoogleCredentials(): Promise<Credentials> {
	const clientKey = azureMultilineEnvFix(process.env.GOOGLE_CLIENT_KEY);

	const jwtClient = new google.auth.JWT(
		process.env.GOOGLE_CLIENT_EMAIL,
		undefined,
		clientKey,
		['openid', 'https://www.googleapis.com/auth/cloud-platform'],
		undefined,
	);
	return jwtClient.authorize();
}

const getGoogleIdToken = async () => {
	const body = JSON.stringify({
		audience: process.env.GOOGLE_CLIENT_EMAIL,
		delegates: [],
		includeEmail: true,
	});
	const headers = new Headers();
	headers.set('Authorization', 'Bearer ' + (await getGoogleCredentials()).access_token);
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

function cachePayloadSchema<T>(data: z.Schema<T>) {
	return z.object({
		data,
		expires: z.number().optional(),
	});
}
const anyObjectSchema = z.object({}).passthrough(); // or build token payload schema
const bufferSerializer: IPersistSerializer<CacheMap<TokenPayload, RawJwtToken>, Buffer> = {
	name: 'bufferSerializer',
	serialize: (data: CacheMap<TokenPayload, RawJwtToken>) => Buffer.from(JSON.stringify(Array.from(data))),
	deserialize: (buffer: Buffer) => new Map(JSON.parse(buffer.toString())),
	validator: (data: CacheMap<TokenPayload, RawJwtToken>) => z.map(z.string(), cachePayloadSchema(anyObjectSchema)).safeParse(data).success,
};
const processor = new CryptoBufferProcessor(Buffer.from('some-secret-key'));
const driver = new FileStorageDriver('TokenStorageDriver', {fileName: './tokenCache.aes'}, bufferSerializer, processor);
const cache = new TachyonExpireCache<TokenPayload, RawJwtToken>('TachyonExpireCache', driver);

describe('jwtUtil', () => {
	before(async function () {
		this.timeout(30000);
		AZURE_ACCESS_TOKEN = await getAzureAccessToken();
		GOOGLE_ID_TOKEN = await getGoogleIdToken();
	});
	describe('jwtVerifyPromise', () => {
		it('should fail internal jwtVerifyPromise with broken data', async () => {
			await expect(jwtVerifyPromise('qwe', 'qwe')).to.be.eventually.rejectedWith(Error, 'jwt malformed');
		});
	});
	describe('jwtVerify', () => {
		it('should fail if broken token format', async () => {
			await expect(jwtVerify('asd')).to.be.eventually.rejectedWith(Error, 'Not JWT token string format');
		});
		it('should fail if broken token', async () => {
			await expect(jwtVerify('asd.asd.asd')).to.be.eventually.rejectedWith(Error, "Can't decode token");
		});
		it('should fail is issuer url is missing', async () => {
			const test = jwtSign({}, 'test');
			await expect(jwtVerify(test)).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: missing issuer parameter');
		});
		it('should fail is kid is missing', async () => {
			const test = jwtSign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(test)).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: missing kid parameter');
		});
		it('should fail if auth type is not Bearer', async () => {
			const test = jwtSign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(`Basic ${test}`)).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: wrong authentication header type');
		});
		it('should not load issuer certs if not allowed', async () => {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			await expect(jwtVerify(GOOGLE_ID_TOKEN, {issuer: []})).to.be.eventually.rejectedWith(JwtHeaderError, 'token header: issuer is not valid');
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
		});
	});
	describe('tokens with FileCertCache', () => {
		before(async () => {
			testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			await useCache(new FileCertCache({fileName: './unitTestCache.json', pretty: true}));
		});
		it('Test Google IdToken', async function () {
			this.slow(100);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			this.slow(5);
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN as string);
			}
		});
		it('Test Google token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(undefined);
			expect(body.aud).not.to.be.eq(undefined);
			expect(body.exp).not.to.be.eq(undefined);
			expect(body.iat).not.to.be.eq(undefined);
			expect(body.iss).not.to.be.eq(undefined);
			expect(body.sub).not.to.be.eq(undefined);
			expect(body.test).to.be.eq(undefined);
			expect(isCached).to.be.eq(true);
		});
		it('Test non Bearer auth', async () => {
			try {
				await jwtBearerVerify('Basic some:fun');
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non issuer token ', async () => {
			const test = jwtSign({test: 'asd'}, 'secret');
			try {
				await jwtVerify(test);
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non-valid issuer', async () => {
			try {
				await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true}) as JwtPayload;
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async function () {
			this.slow(500);
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
		after(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
		});
	});
	describe('tokens with TachyonCertCache', () => {
		before(async () => {
			driver.clear(); // clear token cache
			testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			setTokenCache(cache);
			await useCache(new TachyonCertCache(new FileStorageDriver('FileCertCacheDriver', {fileName: './unitTestCache.json'}, certCacheBufferSerializer)));
		});
		it('Test Google IdToken', async function () {
			this.slow(100);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			setTokenCache(new TachyonExpireCache<TokenPayload, RawJwtToken>('TachyonExpireCache', driver)); // rebuild new cache
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			this.slow(5);
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN as string);
			}
		});
		it('Test Google token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(undefined);
			expect(body.aud).not.to.be.eq(undefined);
			expect(body.exp).not.to.be.eq(undefined);
			expect(body.iat).not.to.be.eq(undefined);
			expect(body.iss).not.to.be.eq(undefined);
			expect(body.sub).not.to.be.eq(undefined);
			expect(body.test).to.be.eq(undefined);
			expect(isCached).to.be.eq(true);
		});
		it('Test non Bearer auth', async () => {
			try {
				await jwtBearerVerify('Basic some:fun');
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non issuer token ', async () => {
			const test = jwtSign({test: 'asd'}, 'secret');
			try {
				await jwtVerify(test);
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non-valid issuer', async () => {
			try {
				await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true}) as JwtPayload;
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async function () {
			this.slow(500);
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
		after(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
		});
	});
	describe('tokens with TachyonCertCache in memory', () => {
		before(async () => {
			cache.clear();
			driver.clear(); // clear token cache
			testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			await useCache(new TachyonCertCache(new MemoryStorageDriver('MemoryCertCacheDriver', certCacheStringSerializer, null)));
		});
		it('Test Google IdToken', async function () {
			this.slow(100);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			setTokenCache(new TachyonExpireCache<TokenPayload, RawJwtToken>('TachyonExpireCache', driver)); // rebuild new cache
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN as string);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			this.slow(5);
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN as string);
			}
		});
		it('Test Google token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(undefined);
			expect(body.aud).not.to.be.eq(undefined);
			expect(body.exp).not.to.be.eq(undefined);
			expect(body.iat).not.to.be.eq(undefined);
			expect(body.iss).not.to.be.eq(undefined);
			expect(body.sub).not.to.be.eq(undefined);
			expect(body.test).to.be.eq(undefined);
			expect(isCached).to.be.eq(true);
		});
		it('Test non Bearer auth', async () => {
			try {
				await jwtBearerVerify('Basic some:fun');
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non issuer token ', async () => {
			const test = jwtSign({test: 'asd'}, 'secret');
			try {
				await jwtVerify(test);
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non-valid issuer', async () => {
			try {
				await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true}) as JwtPayload;
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async function () {
			this.slow(500);
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
	});
	describe('test IssuerCertLoader', () => {
		before(async () => {
			icl = new IssuerCertLoader();
		});
		it('should throw if issuer is not found (hostname error)', async function () {
			this.timeout(10000);
			await expect(icl.getCert('https://123qweasdqwe123zzz/uuaaakkk/', 'unknown')).to.be.rejected;
		});
		it('should throw if issuer is not found (json error)', async () => {
			await expect(icl.getCert('https://google.com', 'unknown')).to.be.rejected;
		});
		it('should throw when get cert for unknown kid ', async () => {
			await expect(icl.getCert('https://accounts.google.com', 'unknown')).to.be.rejectedWith(
				"no key Id 'unknown' found for issuer 'https://accounts.google.com'",
			);
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
	after(async () => {
		driver.clear();
	});
});
