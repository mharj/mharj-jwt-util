export {setJwtLogger} from './logger';
export {FileCertCache} from './cache/FileCertCache';
import * as jwt from 'jsonwebtoken';
import {CertCache} from './cache/CertCache';
import {ExpireCache} from './ExpireCache';
import {IssuerCertLoader} from './issuerCertLoader';
import { JwtHeaderError } from './JwtHeaderError';
import {buildCertFrame} from './rsaPublicKeyPem';
const icl = new IssuerCertLoader();

const cache = new ExpireCache<any>();

export interface ITokenPayloadCommon extends Record<string, any> {
	aud?: string;
	exp?: number;
	iat?: number;
	iss?: string;
	sub?: string;
	nonce?: string;
}

export type ITokenPayload<T = Record<string, any>> = ITokenPayloadCommon & T;

interface ITokenHeader extends Record<string, any> {
	kid?: string;
	alg: jwt.Algorithm | undefined;
	typ: string | undefined;
}

interface ITokenStructure {
	header: ITokenHeader;
	payload: ITokenPayload;
}

let isCached: boolean | undefined;
export const wasItCached = () => {
	return isCached;
};

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

type JwtVerifyPromiseFunc<T = Record<string, any>> = (...params: Parameters<typeof jwt.verify>) => Promise<ITokenPayload<T> | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<ITokenPayload | undefined>((resolve, reject) => {
		jwt.verify(token, secretOrPublicKey, options, (err: jwt.VerifyErrors | null, decoded: object | undefined) => {
			if (err) {
				reject(err);
			} else {
				resolve(decoded);
			}
		});
	});
};

const getKeyIdAndSetOptions = (decoded: ITokenStructure, options: jwt.VerifyOptions | undefined) => {
	const {kid, alg, typ} = decoded.header || {};
	if (!kid) {
		throw new JwtHeaderError('token header: missing kid parameter');
	}
	if (typ !== 'JWT') {
		throw new JwtHeaderError(`token header: type "${typ}" is not valid`);
	}
	if (!options) {
		options = {};
	}
	if (alg) {
		options.algorithms = [alg];
	}
	return kid;
};

/**
 * Verify JWT token against issuer public certs
 * @param token jwt token
 * @param allowedIssuers optional issuer validation
 */
export const jwtVerify = async <T extends object>(token: string, options?: jwt.VerifyOptions | undefined): Promise<T & ITokenPayload> => {
	const cached = cache.get(token);
	if (cached) {
		isCached = true;
		return cached;
	}
	isCached = false;
	const decoded = jwt.decode(token, {complete: true}) as ITokenStructure;
	if (!decoded) {
		throw new Error("Can't decode token");
	}
	if (!decoded.payload.iss) {
		throw new JwtHeaderError('token header: missing issuer parameter');
	}
	const certString = await icl.getCert(decoded.payload.iss, getKeyIdAndSetOptions(decoded, options));
	const verifiedDecode = (await jwtVerifyPromise(token, buildCertFrame(certString), options)) as T & ITokenPayload;
	if (verifiedDecode.exp) {
		cache.put(token, verifiedDecode, verifiedDecode.exp * 1000);
	}
	return verifiedDecode;
};

/**
 * Verify auth "Bearer" header against issuer public certs
 * @param authHeader raw authentication header with ^Bearer prefix
 * @param allowedIssuers optional issuer validation
 */
export const jwtBearerVerify = <T extends object>(authHeader: string, options?: jwt.VerifyOptions | undefined): Promise<ITokenPayload & T> => {
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
