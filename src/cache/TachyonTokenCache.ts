/* eslint-disable @typescript-eslint/no-unsafe-argument */
import {type IPersistSerializer} from 'tachyon-drive';
import {type CacheMap} from 'tachyon-expire-cache';
import {z} from 'zod';
import {type RawJwtToken, type TokenPayload} from '../interfaces/token';

function cachePayloadSchema<T extends TokenPayload>(data: z.ZodObject<T>) {
	return z.object({
		data,
		expires: z.number().optional(),
	});
}

/**
 * Build IPersistSerializer for caching valid tokens in a binary raw format.
 *
 * @param {z.ZodObject<T>} schema Zod schema for the token payload
 * @param {string} [name] Optional name for the serializer
 * @returns {IPersistSerializer<CacheMap<T, RawJwtToken>, Buffer>}
 * @since v0.7.2
 */
export function buildTokenCacheBufferSerializer<T extends TokenPayload>(
	schema: z.ZodObject<T>,
	name?: string,
): IPersistSerializer<CacheMap<T, RawJwtToken>, Buffer> {
	const validator = z.map(z.string(), cachePayloadSchema(schema));
	return {
		name: name ?? 'tokenBufferSerializer',
		serialize: (data: CacheMap<TokenPayload, RawJwtToken>) => Buffer.from(JSON.stringify(Array.from(data))),
		deserialize: (buffer: Buffer) => new Map(JSON.parse(buffer.toString())),
		validator: (data: CacheMap<TokenPayload, RawJwtToken>) => validator.safeParse(data).success,
	};
}

/**
 * Build IPersistSerializer for caching valid tokens in a string raw format.
 *
 * @param {z.ZodObject<T>} schema Zod schema for the token payload
 * @param {string} [name] Optional name for the serializer
 * @returns {IPersistSerializer<CacheMap<T, RawJwtToken>, string>}
 * @since v0.7.2
 */
export function buildTokenCacheStringSerializer<T extends TokenPayload>(
	schema: z.ZodObject<T>,
	name?: string,
): IPersistSerializer<CacheMap<T, RawJwtToken>, string> {
	const validator = z.map(z.string(), cachePayloadSchema(schema));
	return {
		name: name ?? 'tokenStringSerializer',
		serialize: (data: CacheMap<TokenPayload, RawJwtToken>) => JSON.stringify(Array.from(data)),
		deserialize: (buffer: string) => new Map(JSON.parse(buffer)),
		validator: (data: CacheMap<TokenPayload, RawJwtToken>) => validator.safeParse(data).success,
	};
}
