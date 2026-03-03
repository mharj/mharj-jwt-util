import type {ILoggerLike, ISetOptionalLogger} from '@avanio/logger-like';
import * as fs from 'fs';
import type {CertRecords, CertRecordsSchema} from '../interfaces/CertRecords';
import {CertCache} from './CertCache';

interface FileCertCacheProps {
	fileName?: string;
	pretty?: boolean;
	schema: CertRecordsSchema;
	logger?: ILoggerLike;
}

const initialCerts: CertRecords = {
	_ts: 0,
	certs: {},
};

/**
 * FileCertCache is a CertCache implementation that stores the JWT cert records in a file.
 * @since v0.8.0
 * @category CertCache
 * @example
 * const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies CertRecordsSchema;
 * await useCache(new FileCertCache({fileName: './certCache.json', schema: certCacheSchema}));
 */
export class FileCertCache extends CertCache implements ISetOptionalLogger {
	private file: string;
	private pretty: boolean;
	private logger: ILoggerLike | undefined;
	private watcher: fs.FSWatcher | undefined;
	private currentTimestamp = initialCerts._ts;
	private schema: CertRecordsSchema;

	public constructor({fileName, pretty, schema, logger}: FileCertCacheProps) {
		super();
		this.logger = logger;
		this.logger?.info('jwt-util FileCertCache registered');
		this.file = fileName ?? './certCache.json';
		this.pretty = pretty ?? false;
		this.schema = schema;
		this.handleUpdateCallback = this.handleUpdateCallback.bind(this);
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
		const validateResult = await this.schema['~standard'].validate(data);
		if (validateResult.issues) {
			return initialCerts;
		}
		return validateResult.value;
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
				// eslint-disable-next-line @typescript-eslint/unbound-method
				debounceTimeout = setTimeout(this.handleUpdateCallback, 100);
			});
		} catch (err) {
			this.logger?.error('jwt-util FileCertCache:init() watch error:', err);
		}
	}

	private async readCacheFile(): Promise<unknown> {
		if (!fs.existsSync(this.file)) {
			return undefined;
		}
		try {
			return JSON.parse((await fs.promises.readFile(this.file)).toString());
		} catch (_err) {
			return undefined;
		}
	}

	private writeCacheFile(certs: CertRecords): Promise<void> {
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
					const validateResult = await this.schema['~standard'].validate(data);
					if (validateResult.issues) {
						return;
					}
					if (validateResult.value._ts > this.currentTimestamp) {
						this.handleUpdate(validateResult.value);
					}
				} catch (_err) {
					this.logger?.error('jwt-util FileCertCache:watch error:', _err);
					// ignore error
				}
			}
		}
	}
}
