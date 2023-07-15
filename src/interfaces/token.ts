/* eslint-disable @typescript-eslint/no-explicit-any */
import * as jwt from 'jsonwebtoken';
import {JwtHeaderError} from '../JwtHeaderError';

export type RawJwtToken = `${string}.${string}.${string}`;

export function isRawJwtToken(token: unknown): token is RawJwtToken {
	return typeof token === 'string' && token.split('.').length === 3;
}

export interface TokenPayloadCommon extends Record<string, any> {
	aud?: string;
	exp?: number;
	iat?: number;
	iss?: string;
	sub?: string;
	nonce?: string;
}

export interface TokenIssuerPayloadCommon extends TokenPayloadCommon {
	iss: string;
}

export type TokenPayload<T = Record<string, any>> = TokenPayloadCommon & T;
export type TokenIssuerPayload<T = Record<string, any>> = TokenIssuerPayloadCommon & T;

export interface TokenHeader extends Record<string, any> {
	kid?: string;
	alg: jwt.Algorithm | undefined;
	typ: string | undefined;
}

export interface FullDecodedTokenStructure {
	header: TokenHeader;
	payload: TokenPayload;
}

export interface FullDecodedIssuerTokenStructure {
	header: TokenHeader;
	payload: TokenIssuerPayload;
}

export function isIssuerToken(decoded: unknown): decoded is FullDecodedIssuerTokenStructure {
	return (
		typeof decoded === 'object' &&
		decoded !== null &&
		'payload' in (decoded as FullDecodedTokenStructure) &&
		'header' in (decoded as FullDecodedTokenStructure) &&
		typeof (decoded as FullDecodedTokenStructure)?.payload?.iss === 'string'
	);
}

export function assertIssuerToken(decoded: unknown): asserts decoded is FullDecodedIssuerTokenStructure {
	if (!isIssuerToken(decoded)) {
		throw new JwtHeaderError('token header: missing issuer parameter');
	}
}

export function isTokenFullDecoded(decoded: unknown): decoded is FullDecodedTokenStructure {
	return (
		typeof decoded === 'object' && decoded !== null && 'payload' in (decoded as FullDecodedTokenStructure) && 'header' in (decoded as FullDecodedTokenStructure)
	);
}

export function assertIsTokenFullDecoded(decoded: unknown): asserts decoded is FullDecodedTokenStructure {
	if (!isTokenFullDecoded(decoded)) {
		throw new JwtHeaderError("token header: Can't decode token");
	}
}
