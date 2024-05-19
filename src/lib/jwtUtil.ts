import {verify, type VerifyErrors} from 'jsonwebtoken';
import type {TokenPayload} from '../interfaces/token';

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof verify>) => Promise<TokenPayload<T> | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<TokenPayload | undefined>((resolve, reject) => {
		verify(token, secretOrPublicKey, options, (err: VerifyErrors | null, decoded: object | string | undefined) => {
			if (err) {
				reject(err);
			} else {
				if (typeof decoded === 'string') {
					resolve(undefined);
				} else {
					resolve(decoded);
				}
			}
		});
	});
};
