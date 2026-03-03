import type {IPersistSerializer, IStorageDriver} from 'tachyon-drive';
import type {CertRecords, CertRecordsSchema} from '../interfaces/CertRecords';
import {CertCache} from './CertCache';

const initialCerts: CertRecords = {
	_ts: 0,
	certs: {},
};

/**
 * TachyonCertCache is a CertCache implementation that uses Tachyon Drive as the storage driver for caching public cert records.
 * @category CertCache
 */
export class TachyonCertCache extends CertCache {
	private driver: IStorageDriver<CertRecords>;

	public constructor(driver: IStorageDriver<CertRecords>) {
		super();
		this.driver = driver;
		this.driver.on('update', (certs) => {
			if (certs) {
				this.handleUpdate(certs);
			}
		});
	}

	protected async init(): Promise<void> {
		if ((await this.driver.init()) === false) {
			// istanbul ignore next
			throw new Error('Failed to initialize driver');
		}
	}

	protected async load(): Promise<CertRecords> {
		return (await this.driver.hydrate()) ?? initialCerts;
	}

	protected save(certs: CertRecords): void | Promise<void> {
		return this.driver.store(certs);
	}
}

/**
 * Build IPersistSerializer for caching cert records in a string raw format.
 * @param {CertRecordsSchema} schema Standard schema for the cert records
 * @returns {IPersistSerializer<CertRecords, string>}
 * @example
 * const zodCertRecordsSchema = z.object({ _ts: z.number(), certs: z.record(z.string(), z.string()) }) satisfies CertRecordsSchema;
 * const stringSerializer = certCacheStringSerializer(zodCertRecordsSchema);
 * @since v0.8.0
 */
export function certCacheStringSerializer(schema: CertRecordsSchema): IPersistSerializer<CertRecords, string> {
	return {
		name: 'certCacheStringSerializer',
		serialize: (certs: CertRecords): string => JSON.stringify(certs),
		deserialize: (certs: string): CertRecords => JSON.parse(certs) as CertRecords,
		validator: async (certs: CertRecords): Promise<boolean> => !(await schema['~standard'].validate(certs)).issues,
	};
}

/**
 * Build IPersistSerializer for caching cert records in a binary raw format.
 * @param {CertRecordsSchema} schema Standard schema for the cert records
 * @returns {IPersistSerializer<CertRecords, Buffer>}
 * @example
 * const zodCertRecordsSchema = z.object({ _ts: z.number(), certs: z.record(z.string(), z.string()) }) satisfies CertRecordsSchema;
 * const bufferSerializer = certCacheBufferSerializer(zodCertRecordsSchema);
 * @since v0.8.0
 */
export function certCacheBufferSerializer(schema: CertRecordsSchema): IPersistSerializer<CertRecords, Buffer> {
	return {
		name: 'certCacheBufferSerializer',
		serialize: (certs: CertRecords): Buffer => Buffer.from(JSON.stringify(certs)),
		deserialize: (certs: Buffer): CertRecords => JSON.parse(certs.toString()) as CertRecords,
		validator: async (certs: CertRecords): Promise<boolean> => !(await schema['~standard'].validate(certs)).issues,
	};
}
