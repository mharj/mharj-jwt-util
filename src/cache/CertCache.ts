import {CertRecords} from '../interfaces/CertRecords';

export abstract class CertCache {
	protected updateCallback: ((certs: CertRecords) => void) | undefined;
	private ts: number;
	protected abstract init(): Promise<void>;
	protected abstract load(): Promise<CertRecords>;
	protected abstract save(certs: CertRecords): Promise<void>;
	protected handleUpdate(certs: CertRecords) {
		if (this.updateCallback && certs._ts !== this.ts) {
			this.updateCallback(certs);
		}
	}

	public registerChangeCallback(callback: (certs: CertRecords) => void): void {
		this.updateCallback = callback;
	}

	public handleInit(): Promise<void> {
		return this.init();
	}

	public handleLoad(): Promise<CertRecords> {
		return this.load();
	}

	public handleSave(certs: CertRecords): Promise<void> {
		this.ts = certs._ts;
		return this.save(certs);
	}
}
