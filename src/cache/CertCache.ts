import {type CertRecords} from '../interfaces/CertRecords';

export abstract class CertCache {
	protected updateCallback: ((certs: CertRecords) => void) | undefined;
	private ts: number | undefined;
	protected abstract init(): void | Promise<void>;
	protected abstract load(): CertRecords | Promise<CertRecords>;
	protected abstract save(certs: CertRecords): void | Promise<void>;
	protected handleUpdate(certs: CertRecords) {
		if (this.updateCallback && certs._ts !== this.ts) {
			this.updateCallback(certs);
		}
	}

	public registerChangeCallback(callback: (certs: CertRecords) => void): void {
		this.updateCallback = callback;
	}

	public handleInit(): void | Promise<void> {
		return this.init();
	}

	public handleLoad(): CertRecords | Promise<CertRecords> {
		return this.load();
	}

	public handleSave(certs: CertRecords): void | Promise<void> {
		this.ts = certs._ts;
		return this.save(certs);
	}
}
