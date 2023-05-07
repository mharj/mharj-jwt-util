import * as fs from 'fs';
import {CertCache} from './CertCache';
import {CertRecords} from '../issuerCertLoader';
import {logger} from '../logger';

interface IProps {
	fileName?: string;
	pretty?: boolean;
}

const initialCerts: CertRecords = {
	_ts: 0,
	certs: {},
};

export class FileCertCache extends CertCache {
	private file: string;
	private pretty: boolean;

	constructor({fileName, pretty}: IProps = {}) {
		super();
		logger().info(`jwt-util FileCertCache registered`);
		this.file = fileName || './certCache.json';
		this.pretty = pretty || false;
	}

	protected async init(): Promise<void> {
		logger().debug(`jwt-util FileCertCache:init()`);
		// write empty record file if file not exists
		if (!fs.existsSync(this.file)) {
			await fs.promises.writeFile(this.file, JSON.stringify(initialCerts, undefined, this.pretty ? 2 : undefined));
		}
		// watch file changes
		fs.watch(this.file, async (eventType) => {
			if (this.updateCallback && eventType === 'change') {
				logger().debug(`jwt-util FileCertCache:watch ()=> change`);
				const data = JSON.parse((await fs.promises.readFile(this.file)).toString()) as CertRecords;
				this.handleUpdate(data);
			}
		});
	}

	protected async load(): Promise<CertRecords> {
		logger().debug(`jwt-util FileCertCache:load()`);
		if (!fs.existsSync(this.file)) {
			return initialCerts;
		}
		try {
			return JSON.parse((await fs.promises.readFile(this.file)).toString());
		} catch (err) {
			return initialCerts;
		}
	}

	protected save(certs: CertRecords): Promise<void> {
		logger().debug(`jwt-util FileCertCache:save()`);
		return fs.promises.writeFile(this.file, JSON.stringify(certs, undefined, this.pretty ? 2 : undefined));
	}
}
