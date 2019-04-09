import * as jwt from 'jsonwebtoken';
import {IssuerCertLoader} from './issuerCertLoader';
import {buildCertFrame} from './rsaPublicKeyPem';
const icl = new IssuerCertLoader();

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
	alg: string | undefined;
	typ: string | undefined;
}

interface ITokenStructure {
	header: ITokenHeader;
	payload: ITokenPayload;
}
/**
 * Verify JWT token against issuer public certs
 * @param token jwt token
 * @param allowedIssuers optional issuer validation
 */
export const jwtVerify = async <T extends object>(token: string, allowedIssuers?: string[] | undefined): Promise<T & ITokenPayload> => {
	const decoded = jwt.decode(token, {complete: true}) as ITokenStructure;
	const {kid, alg, typ} = decoded.header;
	if (!kid || typ !== 'JWT' || !decoded.payload.iss) {
		throw new Error('token missing required parameters');
	}
	const verifyOptions: jwt.VerifyOptions = {};
	if (allowedIssuers) {
		verifyOptions.issuer = allowedIssuers;
	}
	if (alg) {
		verifyOptions.algorithms = [alg];
	}
	const certString = await icl.getCert(decoded.payload.iss, kid);
	return new Promise((resolve, reject) => {
		jwt.verify(token, buildCertFrame(certString), verifyOptions, (err: Error, verifiedDecode: T & ITokenPayload) => {
			if (err) {
				reject(err);
			} else {
				resolve(verifiedDecode);
			}
		});
	});
};

/**
 * Verify auth "Bearer" header against issuer public certs
 * @param authHeader raw authentication header with ^Bearer prefix
 * @param allowedIssuers optional issuer validation
 */
export const jwtBearerVerify = <T extends object>(authHeader: string, allowedIssuers?: string[]): Promise<ITokenPayload & T> => {
	const match = authHeader.match(/^Bearer (.*?)$/);
	if (!match) {
		throw new Error('No authentication header');
	}
	return jwtVerify(match[1], allowedIssuers);
};

export const jwtDeleteKid = (issuer: string, kid: string) => {
	icl.deleteKid(issuer, kid);
}