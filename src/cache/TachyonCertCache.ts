import {type CertRecords, certRecordsSchema} from '../interfaces/CertRecords';
import {type IPersistSerializer, type IStorageDriver} from 'tachyon-drive';
import {CertCache} from './CertCache';

const initialCerts: CertRecords = {
	_ts: 0,
	certs: {},
};

export class TachyonCertCache extends CertCache {
	private driver: IStorageDriver<CertRecords>;

	constructor(driver: IStorageDriver<CertRecords>) {
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

export const certCacheStringSerializer: IPersistSerializer<CertRecords, string> = {
	name: 'certCacheStringSerializer',
	serialize: (certs: CertRecords): string => JSON.stringify(certs),
	deserialize: (certs: string): CertRecords => JSON.parse(certs) as CertRecords,
	validator: (certs: CertRecords): boolean => certRecordsSchema.safeParse(certs).success,
};

export const certCacheBufferSerializer: IPersistSerializer<CertRecords, Buffer> = {
	name: 'certCacheBufferSerializer',
	serialize: (certs: CertRecords): Buffer => Buffer.from(JSON.stringify(certs)),
	deserialize: (certs: Buffer): CertRecords => JSON.parse(certs.toString()) as CertRecords,
	validator: (certs: CertRecords): boolean => certRecordsSchema.safeParse(certs).success,
};
