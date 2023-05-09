import * as jwt from 'jsonwebtoken';
import {AuthHeader, getTokenOrAuthHeader} from './AuthHeader';
import {FullDecodedIssuerTokenStructure, FullDecodedTokenStructure, isIssuerToken, isTokenFullDecoded, TokenPayload} from './interfaces/token';
import {buildCertFrame} from './rsaPublicKeyPem';
import {CertCache} from './cache/CertCache';
import {ExpireCache} from '@avanio/expire-cache';
import {ILoggerLike} from '@avanio/logger-like';
import {IssuerCertLoader} from './issuerCertLoader';
import {JwtHeaderError} from './JwtHeaderError';
export {FileCertCache} from './cache/FileCertCache';
export {AuthHeader, getTokenOrAuthHeader, getAuthType, isAuthType} from './AuthHeader';

const icl = new IssuerCertLoader();
const cache = new ExpireCache<TokenPayload>();

export function setJwtLogger(logger: ILoggerLike) {
	icl.setLogger(logger);
}

export function useCache(cacheFunctions: CertCache) {
	return icl.setCache(cacheFunctions);
}

export const testGetCache = () => {
	/* istanbul ignore else  */
	if (process.env.NODE_ENV === 'testing') {
		return cache;
	} else {
		throw new Error('only for testing');
	}
};

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof jwt.verify>) => Promise<TokenPayload<T> | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<TokenPayload | undefined>((resolve, reject) => {
		jwt.verify(token, secretOrPublicKey, options, (err: jwt.VerifyErrors | null, decoded: object | undefined) => {
			if (err) {
				reject(err);
			} else {
				resolve(decoded);
			}
		});
	});
};

const getKeyIdAndSetOptions = (decoded: FullDecodedTokenStructure, options: jwt.VerifyOptions = {}) => {
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
};

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
export const jwtVerify = async <T extends object>(tokenOrBearer: string, options: jwt.VerifyOptions = {}): Promise<JwtResponse<T>> => {
	const currentToken = getTokenOrAuthHeader(tokenOrBearer);
	// only allow bearer as auth type
	if (currentToken instanceof AuthHeader && currentToken.type !== 'BEARER') {
		throw new JwtHeaderError('token header: wrong authentication header type');
	}
	const token = currentToken instanceof AuthHeader ? currentToken.credentials : currentToken;
	const cached = cache.get(token);
	if (cached) {
		return {body: cached as TokenPayload & T, isCached: true};
	}
	const decoded = haveValidIssuer(jwt.decode(token, {complete: true}), options);
	const certString = await icl.getCert(decoded.payload.iss, getKeyIdAndSetOptions(decoded, options));
	const verifiedDecode = (await jwtVerifyPromise(token, buildCertFrame(certString), options)) as T & TokenPayload;
	if (verifiedDecode.exp) {
		cache.set(token, verifiedDecode, new Date(verifiedDecode.exp * 1000));
	}
	return {body: verifiedDecode, isCached: false};
};

/**
 * Verify auth "Bearer" header against issuer public certs
 * @param authHeader raw authentication header with ^Bearer prefix
 * @param options jwt verify options
 */
export const jwtBearerVerify = <T extends object>(authHeader: string, options: jwt.VerifyOptions = {}): Promise<JwtResponse<T>> => {
	const match = authHeader.match(/^Bearer (.*?)$/);
	if (!match) {
		throw new Error('No authentication header');
	}
	return jwtVerify(match[1], options);
};

export const jwtDeleteKid = (issuer: string, kid: string) => {
	icl.deleteKid(issuer, kid);
};

export const jwtHaveIssuer = (issuer: string) => {
	return icl.haveIssuer(issuer);
};
