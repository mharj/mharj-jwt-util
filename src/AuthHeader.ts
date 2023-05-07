import {JwtHeaderError} from './JwtHeaderError';

const authTypes = ['BEARER', 'BASIC', 'DIGEST', 'HOBA', 'MUTUAL', 'NEGOTIATE', 'NTLM', 'VAPID', 'AWS4-HMAC-SHA256'] as const;
export type AuthType = (typeof authTypes)[number];

/**
 * AuthType type verify
 */
export function isAuthType(data: unknown): data is AuthType {
	if (typeof data !== 'string') {
		return false;
	}
	data = data.toUpperCase();
	return authTypes.some((t) => t === data);
}

/**
 * builds uppercase AuthType if valid
 */
export function getAuthType(data: unknown): AuthType {
	if (typeof data !== 'string') {
		throw new Error(`${data} is not valid auth header type`);
	}
	data = data.toUpperCase();
	if (!isAuthType(data)) {
		throw new Error(`${data} is not valid auth header type`);
	}
	return data;
}

/**
 * return AuthHeader instance or string
 */
export function getTokenOrAuthHeader(data: unknown): string | AuthHeader {
	if (typeof data !== 'string') {
		throw new JwtHeaderError('token header: token is not a string');
	}
	return AuthHeader.isAuthHeader(data) ? AuthHeader.fromString(data) : data;
}

export class AuthHeader {
	private readonly auth: string;
	public readonly type: AuthType;
	public readonly credentials: string;

	public static isAuthHeader(auth: unknown): auth is string {
		if (!auth || typeof auth !== 'string') {
			return false;
		}
		const [type] = auth.split(' ', 2);
		return isAuthType(type);
	}

	public static fromString(auth: string): AuthHeader {
		return new AuthHeader(auth);
	}

	private constructor(auth: string) {
		const [type, credentials] = auth.split(' ', 2);
		if (!isAuthType(type)) {
			throw new Error(`${type} is not valid auth header type`);
		}
		this.auth = auth;
		this.type = getAuthType(type);
		this.credentials = credentials;
	}

	public toString(): string {
		return this.auth;
	}
}
