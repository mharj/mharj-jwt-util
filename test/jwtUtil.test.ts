process.env.NODE_ENV = 'testing';
import fs from 'node:fs';
import {decode as jwtDecode, JsonWebTokenError, type Jwt, type JwtHeader, type JwtPayload, sign as jwtSign} from 'jsonwebtoken';
import {MemoryStorageDriver} from 'tachyon-drive';
import {CryptoBufferProcessor, FileStorageDriver} from 'tachyon-drive-node-fs';
import {TachyonExpireCache} from 'tachyon-expire-cache';
import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import {z} from 'zod';
import {
	buildCertFrame,
	buildTokenCacheBufferSerializer,
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
import {getAzureAccessToken} from './lib/azure';
import {getGoogleIdToken} from './lib/google';

let GOOGLE_ID_TOKEN: string;
let AZURE_ACCESS_TOKEN: string;
let icl: IssuerCertLoader;

const anyObjectSchema = z.object({}).passthrough(); // or build token payload schema
const bufferSerializer = buildTokenCacheBufferSerializer(anyObjectSchema);
const processor = new CryptoBufferProcessor(Buffer.from('some-secret-key'));
const driver = new FileStorageDriver('TokenStorageDriver', {fileName: './tokenCache.aes'}, bufferSerializer, processor);
const cache = new TachyonExpireCache<TokenPayload, RawJwtToken>('TachyonExpireCache', driver);

let fileCertCache: FileCertCache;

type AsymmetricJwt = {
	header: JwtHeader & {kid: string};
	payload: JwtPayload & {iss: string};
	signature: string;
};

export function isAsymmetricJwt(data: Jwt | undefined | null): asserts data is AsymmetricJwt {
	if (!data) {
		throw Error('not valid AsymmetricJwt');
	}
	if (!('header' in data && 'payload' in data && 'signature' in data)) {
		throw Error('not valid AsymmetricJwt');
	}
	if (!data?.payload || typeof data.payload !== 'object') {
		throw Error('not valid AsymmetricJwt');
	}
	if (!('kid' in data.header)) {
		throw Error('not valid AsymmetricJwt');
	}
	if (!('iss' in data.payload)) {
		throw Error('not valid AsymmetricJwt');
	}
}

describe('jwtUtil', () => {
	beforeAll(async function () {
		[AZURE_ACCESS_TOKEN, GOOGLE_ID_TOKEN] = await Promise.all([getAzureAccessToken(), getGoogleIdToken()]);
	});
	describe('jwtVerifyPromise', () => {
		it('should fail internal jwtVerifyPromise with broken data', async () => {
			await expect(jwtVerifyPromise('qwe', 'qwe')).rejects.toEqual(new JsonWebTokenError('jwt malformed'));
		});
	});
	describe('jwtVerify', () => {
		it('should fail if broken token format', async () => {
			await expect(jwtVerify('asd')).rejects.toEqual(new JwtHeaderError('Not JWT token string format'));
		});
		it('should fail if broken token', async () => {
			await expect(jwtVerify('asd.asd.asd')).rejects.toEqual(new JwtHeaderError("token header: Can't decode token"));
		});
		it('should fail is issuer url is missing', async () => {
			const test = jwtSign({}, 'test');
			await expect(jwtVerify(test)).rejects.toEqual(new JwtHeaderError('token header: missing issuer parameter'));
		});
		it('should fail is kid is missing', async () => {
			const test = jwtSign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(test)).rejects.toEqual(new JwtHeaderError('token header: missing kid parameter'));
		});
		it('should fail if auth type is not Bearer', async () => {
			const test = jwtSign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(`Basic ${test}`)).rejects.toEqual(new JwtHeaderError('token header: wrong authentication header type'));
		});
		it('should not load issuer certs if not allowed', async () => {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			await expect(jwtVerify(GOOGLE_ID_TOKEN, {issuer: []})).rejects.toEqual(new JwtHeaderError('token header: issuer is not valid'));
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
		});
	});
	describe('tokens with FileCertCache', () => {
		beforeAll(async () => {
			await testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			fileCertCache = new FileCertCache({fileName: './unitTestCache.json', pretty: true});
			fileCertCache.setLogger(undefined);
			await useCache(fileCertCache);
		});
		it('Test Google IdToken', async function () {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN);
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
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true});
			isAsymmetricJwt(decoded);
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async function () {
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
		afterAll(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			fileCertCache.close();
		});
	});
	describe('tokens with TachyonCertCache', () => {
		beforeAll(async () => {
			await driver.clear(); // clear token cache
			await testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			setTokenCache(cache);
			await useCache(new TachyonCertCache(new FileStorageDriver('FileCertCacheDriver', {fileName: './unitTestCache.json'}, certCacheBufferSerializer)));
		});
		it('Test Google IdToken', async function () {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			setTokenCache(new TachyonExpireCache<TokenPayload, RawJwtToken>('TachyonExpireCache', driver)); // rebuild new cache
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN);
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
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true});
			isAsymmetricJwt(decoded);
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async function () {
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
		afterAll(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
		});
	});
	describe('tokens with TachyonCertCache in memory', () => {
		beforeAll(async () => {
			await cache.clear();
			await driver.clear(); // clear token cache
			await testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			await useCache(new TachyonCertCache(new MemoryStorageDriver('MemoryCertCacheDriver', certCacheStringSerializer, null)));
		});
		it('Test Google IdToken', async function () {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			setTokenCache(new TachyonExpireCache<TokenPayload, RawJwtToken>('TachyonExpireCache', driver)); // rebuild new cache
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async function () {
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN);
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
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true});
			isAsymmetricJwt(decoded);
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify('Bearer ' + GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async function () {
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
	});
	describe('test IssuerCertLoader', () => {
		beforeAll(() => {
			icl = new IssuerCertLoader();
		});
		it('should throw if issuer is not found (hostname error)', async function () {
			await expect(icl.getCert('https://123qweasdqwe123zzz/uuaaakkk/', 'unknown')).rejects.toEqual(
				new Error('pullIssuerCerts https://123qweasdqwe123zzz/uuaaakkk/ fetch failed'),
			);
		});
		it('should throw if issuer is not found (json error)', async () => {
			await expect(icl.getCert('https://google.com', 'unknown')).rejects.toEqual(new Error('pullIssuerCerts https://google.com fetch error: Not Found'));
		});
		it('should throw when get cert for unknown kid ', async () => {
			await expect(icl.getCert('https://accounts.google.com', 'unknown')).rejects.toEqual(
				new Error("no key Id 'unknown' found for issuer 'https://accounts.google.com'"),
			);
		});
	});
	describe('test buildCertFrame', () => {
		it('should get RSA PUBLIC key structure as Buffer', () => {
			const data = Buffer.from(
				'MIIBCgKCAQEA18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf//7pVEVJJyDuL5a8PARRYQtH68w+0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M/8pJ6qiOjvjF9bhEq0CC/f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9/NdCUuCsdqavd4T+VWnbplbB8YsC+R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE+nCIDwIDAQAB',
			);
			expect(buildCertFrame(data)).to.be.a.instanceof(Buffer);
		});
		it('should fail if not correct Buffer', () => {
			expect(buildCertFrame.bind(null, Buffer.from(''))).to.be.throw('Cert data error');
		});
		it('should get secret key as string', () => {
			const data = 'secretKey';
			expect(buildCertFrame(data)).to.be.a('string');
		});
	});
	afterAll(async () => {
		await driver.clear();
	});
});
