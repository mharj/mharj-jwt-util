import * as fs from 'fs';
import {type CertRecords, isCertRecords} from '../interfaces/CertRecords';
import {type ILoggerLike, type ISetOptionalLogger} from '@avanio/logger-like';
import {CertCache} from './CertCache';

interface IProps {
	fileName?: string;
	pretty?: boolean;
}

const initialCerts: CertRecords = {
	_ts: 0,
	certs: {},
};

/**
 * FileCertCache is a CertCache implementation that stores the JWT cert records in a file.
 */
export class FileCertCache extends CertCache implements ISetOptionalLogger {
	private file: string;
	private pretty: boolean;
	private logger: ILoggerLike | undefined;
	private watcher: fs.FSWatcher | undefined;
	private currentTimestamp = initialCerts._ts;

	constructor({fileName, pretty}: IProps = {}, logger?: ILoggerLike) {
		super();
		this.logger = logger;
		this.logger?.info('jwt-util FileCertCache registered');
		this.file = fileName ?? './certCache.json';
		this.pretty = pretty ?? false;
	}

	public setLogger(logger: ILoggerLike | undefined) {
		this.logger = logger;
	}

	public close(): void {
		this.logger?.debug('jwt-util FileCertCache:close()');
		this.watcher?.close();
	}

	protected async init(): Promise<void> {
		this.logger?.debug('jwt-util FileCertCache:init()');
		// write empty record file if file not exists
		if (!fs.existsSync(this.file)) {
			await this.writeCacheFile(initialCerts);
		}
		// start watch file changes
		this.initializeWatcher();
	}

	protected async load(): Promise<CertRecords> {
		this.logger?.debug('jwt-util FileCertCache:load()');
		const data = await this.readCacheFile();
		return isCertRecords(data) ? data : initialCerts;
	}

	protected save(certs: CertRecords): Promise<void> {
		this.logger?.debug('jwt-util FileCertCache:save()');
		return this.writeCacheFile(certs);
	}

	private initializeWatcher() {
		try {
			let debounceTimeout: NodeJS.Timeout | null = null;
			// watcher causes multiple events for a single change, so debounce the events
			this.watcher = fs.watch(this.file, () => {
				if (debounceTimeout) {
					clearTimeout(debounceTimeout);
				}
				debounceTimeout = setTimeout(this.handleUpdateCallback, 100);
			});
		} catch (err) {
			this.logger?.error('jwt-util FileCertCache:init() watch error:', err);
		}
	}

	private async readCacheFile(): Promise<unknown | undefined> {
		if (!fs.existsSync(this.file)) {
			return undefined;
		}
		try {
			return JSON.parse((await fs.promises.readFile(this.file)).toString());
		} catch (_err) {
			return undefined;
		}
	}

	private async writeCacheFile(certs: CertRecords): Promise<void> {
		// Store the current timestamp to ensure the watcher skips changes made by this instance
		this.currentTimestamp = certs._ts;
		return fs.promises.writeFile(this.file, JSON.stringify(certs, null, this.pretty ? 2 : undefined));
	}

	/**
	 * Handle the update of the cache file from the watcher.
	 */
	private async handleUpdateCallback() {
		if (this.updateCallback) {
			this.logger?.debug('jwt-util FileCertCache:watch ()=> change');
			if (fs.existsSync(this.file)) {
				try {
					const data = await this.readCacheFile();
					if (isCertRecords(data) && data._ts > this.currentTimestamp) {
						this.handleUpdate(data);
					}
				} catch (_err) {
					this.logger?.error('jwt-util FileCertCache:watch error:', _err);
					// ignore error
				}
			}
		}
	}
}
