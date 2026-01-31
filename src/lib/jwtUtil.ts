import * as jwt from 'jsonwebtoken';
import type {TokenPayload} from '../interfaces/token';

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof jwt.verify>) => Promise<TokenPayload<T> | undefined>;
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<TokenPayload | undefined>((resolve, reject) => {
		jwt.verify(token, secretOrPublicKey, options, (err: jwt.VerifyErrors | null, decoded: object | string | undefined) => {
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
