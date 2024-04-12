import {AuthHeader, isAuthHeaderLikeString} from '@avanio/auth-header';
import {JwtHeaderError} from './JwtHeaderError';

/**
 * return AuthHeader instance or string
 */
export function getTokenOrAuthHeader(data: unknown): string | AuthHeader {
	if (typeof data !== 'string') {
		throw new JwtHeaderError('token header: token is not a string');
	}
	return isAuthHeaderLikeString(data) ? AuthHeader.fromString(data) : data;
}
