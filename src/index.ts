import * as jwt from 'jsonwebtoken';
import { ExpireCache } from './ExpireCache';
import { IssuerCertLoader } from './issuerCertLoader';
import { buildCertFrame } from './rsaPublicKeyPem';
const icl = new IssuerCertLoader();

const cache = new ExpireCache<any>();

export interface ITokenPayload {
	aud?: string;
	exp?: number;
	iat?: number;
	iss?: string;
	sub?: string;
	nonce?: string;
}

interface ITokenHeader {
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

export const testGetCache = () => {
	if (process.env.NODE_ENV === 'testing') {
		return cache;
	} else {
		throw new Error('only for testing');
	}
};
type secretOrPublicKeyType = string | Buffer | {
	key: string | Buffer;
	passphrase: string;
} | jwt.GetPublicKeyOrSecret;
const jwtVerifyPromise = (token: string, secretOrPublicKey: secretOrPublicKeyType, options?: jwt.VerifyOptions | undefined): Promise<object | undefined> => {
	return new Promise<object | undefined>((resolve, reject) => {
		jwt.verify(token, secretOrPublicKey, options, (err: jwt.VerifyErrors | null, decoded: object | undefined) => {
			if (err) {
				reject(err);
			} else {
				resolve(decoded);
			}
		});
	});
}

const getKeyIdAndSetOptions = (decoded: ITokenStructure, options: jwt.VerifyOptions | undefined) => {
	const { kid, alg, typ } = decoded.header;
	if (!kid || typ !== 'JWT') {
		throw new Error('token missing required parameters');
	}
	if (!options) {
		options = {};
	}
	if (alg) {
		options.algorithms = [alg];
	}
	return kid;
}

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
	const decoded = jwt.decode(token, { complete: true }) as ITokenStructure;
	if (!decoded) {
		throw new Error("Can't decode token");
	}
	if (!decoded.payload.iss) {
		throw new Error('token missing required parameters');
	}
	const certString = await icl.getCert(decoded.payload.iss, getKeyIdAndSetOptions(decoded, options));
	const verifiedDecode = await jwtVerifyPromise(token, buildCertFrame(certString), options) as unknown as T & ITokenPayload;
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
