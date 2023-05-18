// import {certItemSchema} from './ICertItem';
import {z} from 'zod';

const issuerUrl = z.string().url();

const keyId = z.string();

export const certIssuerRecordSchema = z.record(keyId, z.string().optional());

export type CertIssuerRecord = z.infer<typeof certIssuerRecordSchema>;

export const certRecordsSchema = z.object({
	_ts: z.number(),
	certs: z.record(issuerUrl, certIssuerRecordSchema),
});

export type CertRecords = z.infer<typeof certRecordsSchema>;

export function isCertRecords(obj: unknown): obj is CertRecords {
	return certRecordsSchema.safeParse(obj).success;
}
