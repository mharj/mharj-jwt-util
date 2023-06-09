import * as jwt from 'jsonwebtoken';
import {TokenPayload} from '../interfaces/token';

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
