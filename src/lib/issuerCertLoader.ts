import {type CertIssuerRecord, type CertRecords} from '../interfaces/CertRecords';
import {ExpireCache, type ExpireCacheLogMapType} from '@avanio/expire-cache';
import {type ILoggerLike, type ISetOptionalLogger} from '@avanio/logger-like';
import {type OpenIdConfig, openIdConfigSchema} from '../interfaces/OpenIdConfig';
import {type OpenIdConfigCerts, openIdConfigCertsSchema} from '../interfaces/OpenIdConfigCerts';
import {type CertCache} from '../cache/CertCache';
import {formatZodError} from './zodUtils';
import {type JsonWebKey} from '../interfaces/JsonWebKey';
import {posix as path} from 'path';
import {rsaPublicKeyPem} from './rsaPublicKeyPem';
import {URL} from 'url';
import {assertZodError, getError} from '.';

export type IssuerCertLoaderOptions = {
	/**
	 * Log mapping for ExpireCache (optional)
	 */
	expireCacheLogMap?: Partial<ExpireCacheLogMapType>;
};

export class IssuerCertLoader implements ISetOptionalLogger {
	private store: CertRecords = {_ts: 0, certs: {}};
	/**
	 * Cache for public certificates
	 */
	private cache: CertCache | undefined;
	private cacheLoaded = false;
	/**
	 * Cache for OpenId configs
	 */
	private configCache: ExpireCache<OpenIdConfig>;
	private logger: ILoggerLike | undefined;

	constructor(logger?: ILoggerLike, {expireCacheLogMap}: IssuerCertLoaderOptions = {}) {
		this.logger = logger;
		this.configCache = new ExpireCache<OpenIdConfig>(this.logger, expireCacheLogMap, 86400000); // default OpenId config cache for 24 hours
	}

	public setLogger(logger: ILoggerLike | undefined) {
		this.logger = logger;
		this.configCache.setLogger(logger);
	}

	public async setCache(cache: CertCache) {
		this.cache = cache;
		await this.cache.handleInit();
		this.cache.registerChangeCallback((certs) => {
			this.logger?.debug(`jwt-util handleUpdate ${this.countCerts()} certificates`);
			this.store = certs;
			this.cacheLoaded = true;
		});
	}

	public async getCert(issuerUrl: string, kid: string): Promise<Buffer | string> {
		this.logger?.debug(`jwt-util getCert ${issuerUrl} ${kid}`);
		if (!this.cacheLoaded && this.cache) {
			this.store = await this.cache.handleLoad();
			this.logger?.debug(`jwt-util cacheLoaded ${this.countCerts()} certificates`);
			this.cacheLoaded = true;
		}
		const certIssuerRecord = await this.getIssuerCerts(issuerUrl);
		return this.getIssuerCert(certIssuerRecord, issuerUrl, kid);
	}

	public deleteKid(issuerUrl: string, kid: string): boolean {
		this.logger?.debug(`jwt-util deleteKid ${issuerUrl} ${kid}`);
		const issuerRecord = this.store.certs[issuerUrl];
		if (issuerRecord?.[kid]) {
			delete issuerRecord[kid];
			return true;
		}
		return false;
	}

	public haveIssuer(issuerUrl: string): boolean {
		return Boolean(this.store.certs[issuerUrl]);
	}

	private async getIssuerCert(certIssuerRecord: CertIssuerRecord, issuerUrl: string, kid: string): Promise<Buffer> {
		let cert = certIssuerRecord[kid];
		if (!cert) {
			// we didn't find kid, reload all issuer certs
			certIssuerRecord = await this.pullIssuerCerts(issuerUrl);
		}
		cert = certIssuerRecord[kid];
		if (!cert) {
			// after issuer certs update, we still don't have cert for kid, throw out
			throw new Error(`no key Id '${kid}' found for issuer '${issuerUrl}'`);
		}
		return Buffer.from(cert);
	}

	private async getIssuerCerts(issuerUrl: string): Promise<CertIssuerRecord> {
		let issuer = this.store.certs[issuerUrl];
		if (!issuer) {
			issuer = await this.pullIssuerCerts(issuerUrl);
		}
		/* istanbul ignore if  */
		if (!issuer) {
			throw new Error(`no '${issuerUrl}' found!`);
		}
		return issuer;
	}

	private async pullIssuerCerts(issuerUrl: string): Promise<CertIssuerRecord> {
		try {
			this.logger?.debug(`jwt-util pullIssuerCerts ${issuerUrl}`);
			const certList = await this.getCertList(issuerUrl);
			const output = certList.keys.reduce<CertIssuerRecord>((last, current) => {
				last[current.kid] = this.buildStringCert(current);
				return last;
			}, {});

			this.store.certs[issuerUrl] = output; // update store with latest issuer certs
			await this.saveCerts(); // we have store change
			return output;
		} catch (e) {
			throw new Error(`pullIssuerCerts ${issuerUrl} ${getError(e).message}`);
		}
	}

	private async saveCerts() {
		this.store._ts = new Date().getTime(); // update timestamp
		if (this.cache) {
			this.logger?.debug(`jwt-util cacheSaved ${this.countCerts()} certificates`);
			await this.cache.handleSave(this.store);
		}
	}

	/**
	 * Loops through all issuer certs and counts them
	 */
	private countCerts() {
		return Object.values(this.store.certs).reduce((last, current) => {
			return last + Object.keys(current).length;
		}, 0);
	}

	/**
	 * takes cert item and builds PEM string (from x5c or n and e)
	 */
	private buildStringCert(cert: JsonWebKey): string {
		/* istanbul ignore else if  */
		if (cert.n && cert.e) {
			// we have modulo and exponent, build PEM to cert.x5c
			return rsaPublicKeyPem(cert.n, cert.e);
		}
		if (cert.x5c) {
			return cert.x5c[0];
		} else {
			throw new Error('no cert found');
		}
	}

	/**
	 * Get cert list from issuer.
	 */
	private async getCertList(issuerUrl: string): Promise<OpenIdConfigCerts> {
		this.logger?.debug(`jwt-util getCertList ${issuerUrl}`);
		const config = await this.getConfiguration(issuerUrl);
		const req = new Request(config.jwks_uri);
		const res = await fetch(req);
		const data = (await this.isValidResp(res).json()) as unknown;
		this.isValidJwtUriData(data);
		return data;
	}

	/**
	 * Get OpenId Configuration from issuer.
	 *
	 * - Uses cache if available
	 * - If not in cache, downloads from issuer
	 * - Caches config for 24h
	 */
	private async getConfiguration(issuerUrl: string): Promise<OpenIdConfig> {
		const currentConfig = this.configCache.get(issuerUrl);
		if (currentConfig) {
			return currentConfig;
		} else {
			const config = await this.fetchOpenIdConfig(issuerUrl);
			this.configCache.set(issuerUrl, config, new Date(Date.now() + 86400000)); // cache config 24h
			return config;
		}
	}

	/**
	 * Download OpenId Configuration from issuer.
	 */
	private async fetchOpenIdConfig(issuerUrl: string): Promise<OpenIdConfig> {
		const issuerObj = new URL(issuerUrl);
		issuerObj.pathname = path.join(issuerObj.pathname, '/.well-known/openid-configuration');
		this.logger?.debug(`jwt-util get JWT Configuration ${issuerObj.href}`);
		const req = new Request(issuerObj);
		const res = await fetch(req);
		const data = (await this.isValidResp(res).json()) as unknown;
		this.isValidOpenIdConfig(data);
		return data;
	}

	/**
	 * Check if response is valid.
	 *
	 * - Ensure that response status is 200.
	 */
	private isValidResp(resp: Response): Response {
		if (resp.status !== 200) {
			throw new Error('fetch error: ' + resp.statusText);
		}
		return resp;
	}

	/**
	 * Check if data is valid OpenID Config.
	 *
	 * - Ensure that data is not null and is an object type
	 * - Ensure that data object has a jwks_uri key.
	 */
	private isValidOpenIdConfig(data: unknown): asserts data is OpenIdConfig {
		try {
			openIdConfigSchema.parse(data);
		} catch (e) {
			assertZodError(e);
			throw formatZodError(e);
		}
	}

	/**
	 * Check if data is valid JWT URI data.
	 *
	 * - Ensure that data is not null and is an object type
	 * - Ensure that data object has a keys key.
	 */
	private isValidJwtUriData(data: unknown): asserts data is OpenIdConfigCerts {
		try {
			openIdConfigCertsSchema.parse(data);
		} catch (e) {
			assertZodError(e);
			throw formatZodError(e);
		}
	}
}
