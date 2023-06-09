import {CertRecords, certRecordsSchema} from '../interfaces/CertRecords';
import {IPersistSerializer, IStorageDriver} from 'tachyon-drive';
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
	}

	protected async init(): Promise<void> {
		if ((await this.driver.init()) === false) {
			throw new Error('Failed to initialize driver');
		}
	}

	protected async load(): Promise<CertRecords> {
		return (await this.driver.hydrate()) || initialCerts;
	}

	protected save(certs: CertRecords): Promise<void> {
		return this.driver.store(certs);
	}
}

export const certCacheStringSerializer: IPersistSerializer<CertRecords, string> = {
	serialize: (certs: CertRecords): string => JSON.stringify(certs),
	deserialize: (certs: string): CertRecords => JSON.parse(certs),
	validator: (certs: CertRecords): boolean => certRecordsSchema.safeParse(certs).success,
};

export const certCacheBufferSerializer: IPersistSerializer<CertRecords, Buffer> = {
	serialize: (certs: CertRecords): Buffer => Buffer.from(JSON.stringify(certs)),
	deserialize: (certs: Buffer): CertRecords => JSON.parse(certs.toString()),
	validator: (certs: CertRecords): boolean => certRecordsSchema.safeParse(certs).success,
};
