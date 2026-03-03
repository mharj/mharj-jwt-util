import type {StandardSchemaV1} from '@standard-schema/spec';
import type {IPersistSerializer} from 'tachyon-drive';
import type {RawJwtToken, TokenPayload} from '../interfaces/token';

export type CacheMap<T> = Map<RawJwtToken, {data: T; expires: number}>;

export type TokenCacheMapSchema<T> = StandardSchemaV1<unknown, CacheMap<T>>;

/**
 * Build IPersistSerializer for caching valid tokens in a binary raw format.
 *
 * @param {TokenCacheMapSchema<T>} schema Standard schema for the token payload
 * @param {string} [name] Optional name for the serializer
 * @returns {IPersistSerializer<CacheMap<T>, Buffer>}
 * @category TokenCache
 * @example
 * const tokenBodySchema = z.object({}).passthrough(); // or build token payload schema
 * const zodTokenCacheMapSchema = z.map(z.string(), z.object({expires: z.number().optional(), data: tokenBodySchema})); // or build token payload schema
 * const bufferSerializer = buildTokenCacheBufferSerializer(zodTokenCacheMapSchema);
 * @since v0.8.0
 */
export function buildTokenCacheBufferSerializer<T extends TokenPayload>(
	schema: TokenCacheMapSchema<T>,
	name?: string,
): IPersistSerializer<CacheMap<T>, Buffer> {
	return {
		name: name ?? 'tokenBufferSerializer',
		serialize: (data: CacheMap<T>) => Buffer.from(JSON.stringify(Array.from(data))),
		deserialize: (buffer: Buffer) => new Map(JSON.parse(buffer.toString())),
		validator: async (data: CacheMap<T>) => !(await schema['~standard'].validate(data)).issues,
	};
}

/**
 * Build IPersistSerializer for caching valid tokens in a string raw format.
 *
 * @param {TokenCacheMapSchema<T>} schema Standard schema for the token payload
 * @param {string} [name] Optional name for the serializer
 * @returns {IPersistSerializer<CacheMap<T>, string>}
 * @category TokenCache
 * @example
 * const tokenBodySchema = z.object({}).passthrough(); // or build token payload schema
 * const zodTokenCacheMapSchema = z.map(z.string(), z.object({expires: z.number().optional(), data: tokenBodySchema})); // or build token payload schema
 * const stringSerializer = buildTokenCacheStringSerializer(zodTokenCacheMapSchema);
 * @since v0.8.0
 */
export function buildTokenCacheStringSerializer<T extends TokenPayload>(
	schema: TokenCacheMapSchema<T>,
	name?: string,
): IPersistSerializer<CacheMap<T>, string> {
	return {
		name: name ?? 'tokenStringSerializer',
		serialize: (data: CacheMap<T>) => JSON.stringify(Array.from(data)),
		deserialize: (buffer: string) => new Map(JSON.parse(buffer)),
		validator: async (data: CacheMap<T>) => !(await schema['~standard'].validate(data)).issues,
	};
}
