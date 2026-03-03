import type {StandardSchemaV1} from '@standard-schema/spec';

export type CertIssuerRecord = Record<string, string | undefined>;

export type CertRecords = {
	_ts: number;
	certs: Record<string, CertIssuerRecord>;
};

/**
 * Standard schema for the public cert records
 * @since v0.8.0
 * @example
 * const certRecordsSchema = z.object({ _ts: z.number(), certs: z.record(z.string(), z.record(z.string(), z.string())) }) satisfies StandardSchemaV1<unknown, CertRecords>;
 */
export type CertRecordsSchema = StandardSchemaV1<unknown, CertRecords>;
