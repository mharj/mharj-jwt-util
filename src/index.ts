import * as jwt from 'jsonwebtoken';
import {ExpireCache, ICacheOrAsync} from '@avanio/expire-cache';
import {
	FullDecodedIssuerTokenStructure,
	FullDecodedTokenStructure,
	isIssuerToken,
	isRawJwtToken,
	isTokenFullDecoded,
	RawJwtToken,
	TokenPayload,
} from './interfaces/token';
import {AuthHeader} from '@avanio/auth-header';
import {buildCertFrame} from './rsaPublicKeyPem';
import {CertCache} from './cache/CertCache';
import {getTokenOrAuthHeader} from './lib/authUtil';
import {ILoggerLike} from '@avanio/logger-like';
import {IssuerCertLoader} from './issuerCertLoader';
import {JwtHeaderError} from './JwtHeaderError';
import {jwtVerifyPromise} from './lib/jwtUtil';
export * from './cache/FileCertCache';
export * from './cache/TachyonCertCache';
export * from './lib/jwtUtil';
export * from './interfaces/token';

/**
 * Default instance of IssuerCertLoader
 */
let certLoaderInstance = new IssuerCertLoader();

/**
 * Cache for resolved token payloads, default is in memory cache
 */
let tokenCache: ICacheOrAsync<TokenPayload, RawJwtToken> = new ExpireCache<TokenPayload, RawJwtToken>();
/***
 * Setup token cache for verified payloads, on production this should be encrypted if persisted
 */
export function setTokenCache(cache: ICacheOrAsync<TokenPayload, RawJwtToken>) {
	tokenCache = cache;
}

export function setJwtLogger(logger: ILoggerLike) {
	certLoaderInstance.setLogger(logger);
}

/**
 * Setup cache for public certificates
 */
export function useCache(cacheFunctions: CertCache) {
	return certLoaderInstance.setCache(cacheFunctions);
}

export function testGetCache(): ICacheOrAsync<TokenPayload> {
	/* istanbul ignore else  */
	if (process.env.NODE_ENV === 'testing') {
		return tokenCache;
	} else {
		throw new Error('only for testing');
	}
}

export function setCertLoader(newIcl: IssuerCertLoader) {
	/* istanbul ignore else  */
	if (process.env.NODE_ENV === 'testing') {
		certLoaderInstance = newIcl;
	} else {
		throw new Error('only for testing');
	}
}

function getKeyIdAndSetOptions(decoded: FullDecodedTokenStructure, options: jwt.VerifyOptions = {}) {
	const {kid, alg, typ} = decoded.header || {};
	if (!kid) {
		throw new JwtHeaderError('token header: missing kid parameter');
	}
	if (typ !== 'JWT') {
		throw new JwtHeaderError(`token header: type "${typ}" is not valid`);
	}
	if (alg) {
		options.algorithms = [alg];
	}
	return kid;
}

/**
 * Validate full decoded token object that body have "iss" set
 * @param decoded complete jwt decode with header
 * @param options jwt verification options
 * @returns IIssuerTokenStructure which have "iss" and valid issuer if limited on options
 */
function haveValidIssuer(decoded: unknown, options: jwt.VerifyOptions): FullDecodedIssuerTokenStructure {
	if (!isTokenFullDecoded(decoded)) {
		throw new JwtHeaderError("token header: Can't decode token");
	}
	if (!isIssuerToken(decoded)) {
		throw new JwtHeaderError('token header: missing issuer parameter');
	}
	if (options.issuer) {
		// prevent loading rogue issuers data if not valid issuer
		const allowedIssuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
		if (!allowedIssuers.includes(decoded.payload.iss)) {
			throw new JwtHeaderError('token header: issuer is not valid');
		}
	}
	return decoded;
}

/**
 * Response have decoded body and information if was already verified and returned from cache
 */
export type JwtResponse<T extends object> = {body: T & TokenPayload; isCached: boolean};
/**
 * Verify JWT token against issuer public certs
 * @param tokenOrBearer jwt token or Bearer string with jwt token
 * @param options jwt verify options
 */
export async function jwtVerify<T extends object>(tokenOrBearer: string, options: jwt.VerifyOptions = {}): Promise<JwtResponse<T>> {
	const currentToken = getTokenOrAuthHeader(tokenOrBearer);
	// only allow bearer as auth type
	if (currentToken instanceof AuthHeader && currentToken.type !== 'BEARER') {
		throw new JwtHeaderError('token header: wrong authentication header type');
	}
	const token = currentToken instanceof AuthHeader ? currentToken.credentials : currentToken;
	if (!isRawJwtToken(token)) {
		throw new JwtHeaderError('Not JWT token string format');
	}
	const cached = await tokenCache.get(token);
	if (cached) {
		return {body: cached as TokenPayload & T, isCached: true};
	}
	const decoded = haveValidIssuer(jwt.decode(token, {complete: true}), options);
	const certString = await certLoaderInstance.getCert(decoded.payload.iss, getKeyIdAndSetOptions(decoded, options));
	const verifiedDecode = (await jwtVerifyPromise(token, buildCertFrame(certString), options)) as T & TokenPayload;
	if (verifiedDecode.exp) {
		await tokenCache.set(token, verifiedDecode, new Date(verifiedDecode.exp * 1000));
	}
	return {body: verifiedDecode, isCached: false};
}

/**
 * Verify auth "Bearer" header against issuer public certs
 * @param authHeader raw authentication header with ^Bearer prefix
 * @param options jwt verify options
 */
export function jwtBearerVerify<T extends object>(authHeader: string, options: jwt.VerifyOptions = {}): Promise<JwtResponse<T>> {
	const match = authHeader.match(/^Bearer (.*?)$/);
	if (!match) {
		throw new Error('No authentication header');
	}
	return jwtVerify(match[1], options);
}

export function jwtDeleteKid(issuer: string, kid: string) {
	certLoaderInstance.deleteKid(issuer, kid);
}

export function jwtHaveIssuer(issuer: string) {
	return certLoaderInstance.haveIssuer(issuer);
}
