import 'cross-fetch/polyfill';
import {CertCache} from './cache/CertCache';
import {ExpireCache} from '@avanio/expire-cache';
import {logger} from './logger';
import {posix as path} from 'path';
import {rsaPublicKeyPem} from './rsaPublicKeyPem';
import {URL} from 'url';

interface ICertItem {
	alg?: string;
	kty: string;
	use: string;
	kid: string;
	x5t?: string;
	n: string;
	e: string;
	x5c?: string[];
	issuer?: string;
}

type IssuerUrl = string;

export interface CertRecords {
	_ts: number;
	certs: Record<IssuerUrl, ICertItem[] | undefined>;
}

interface IOpenIdConfig {
	jwks_uri: string;
}

interface ICertList {
	keys: ICertItem[];
}

export class IssuerCertLoader {
	private store: CertRecords = {_ts: 0, certs: {}};
	private cache: CertCache | undefined;
	private cacheLoaded = false;
	private configCache = new ExpireCache<IOpenIdConfig>();

	public async setCache(cache: CertCache) {
		this.cache = cache;
		await this.cache.handleInit();
		this.cache.registerChangeCallback((certs) => {
			logger().debug(`jwt-util handleUpdate ${this.countCerts()} certificates`);
			this.store = certs;
			this.cacheLoaded = true;
		});
	}

	public async getCert(issuerUrl: string, kid: string): Promise<Buffer | string> {
		if (!this.cacheLoaded && this.cache) {
			this.store = await this.cache.handleLoad();
			logger().debug(`jwt-util cacheLoaded ${this.countCerts()} certificates`);
			this.cacheLoaded = true;
		}
		const certList = await this.getIssuerCerts(issuerUrl);
		const cert = await this.getIssuerCert(certList, issuerUrl, kid);
		return this.buildCert(cert);
	}

	public deleteKid(issuerUrl: string, kid: string): boolean {
		const issuer = this.store.certs[issuerUrl];
		if (issuer) {
			const certIndex = issuer.findIndex((c) => c.kid === kid);
			if (certIndex !== -1) {
				issuer.splice(certIndex, 1);
				return true;
			}
		}
		return false;
	}

	public haveIssuer(issuerUrl: string): boolean {
		return Boolean(this.store.certs[issuerUrl]);
	}

	private async getIssuerCert(certList: ICertItem[], issuerUrl: string, kid: string) {
		let cert = certList.find((c) => c.kid === kid);
		if (!cert) {
			// we didn't find kid, reload all issuer certs
			certList = await this.pullIssuerCerts(issuerUrl);
		}
		cert = certList.find((c) => c.kid === kid);
		if (!cert) {
			// after issuer certs update, we still don't have cert for kid, throw out
			throw new Error(`no key Id '${kid}' found for issuer '${issuerUrl}'`);
		}
		return cert;
	}

	private async getIssuerCerts(issuerUrl: string): Promise<ICertItem[]> {
		let issuer = this.store.certs[issuerUrl];
		if (!issuer) {
			issuer = await this.pullIssuerCerts(issuerUrl);
		}
		/* istanbul ignore if  */
		if (!issuer) {
			throw new Error(`no '${issuer}' found!`);
		}
		return issuer;
	}

	private async pullIssuerCerts(issuerUrl: string): Promise<ICertItem[]> {
		const certList = await this.getCertList(issuerUrl);
		this.store.certs[issuerUrl] = certList.keys;
		await this.saveCerts(); // we have a change
		return this.store.certs[issuerUrl] as ICertItem[];
	}

	private async saveCerts() {
		this.store._ts = new Date().getTime(); // update timestamp
		if (this.cache) {
			logger().debug(`jwt-util cacheSaved ${this.countCerts()} certificates`);
			await this.cache.handleSave(this.store);
		}
	}

	private countCerts() {
		return Object.values(this.store.certs).reduce((last, current) => last + (current?.length || 0), 0);
	}

	private buildCert(cert: ICertItem): Buffer {
		/* istanbul ignore else if  */
		if (cert.n && cert.e) {
			// we have modulo and exponent, build PEM to cert.x5c
			cert.x5c = [rsaPublicKeyPem(cert.n, cert.e)];
		}
		if (cert.x5c) {
			return Buffer.from(cert.x5c[0]);
		} else {
			throw new Error('no cert found');
		}
	}

	private async getCertList(issuerUrl: string): Promise<ICertList> {
		logger().debug(`jwt-util getCertList ${issuerUrl}`);
		const config = await this.getConfiguration(issuerUrl);
		const req = new Request(config.jwks_uri);
		return fetch(req).then((resp) => this.isValidResp(resp).json());
	}

	private async getConfiguration(issuerUrl: string): Promise<IOpenIdConfig> {
		const currentConfig = this.configCache.get(issuerUrl);
		if (currentConfig) {
			return currentConfig;
		} else {
			const config = await this.fetchOpenIdConfig(issuerUrl);
			this.configCache.set(issuerUrl, config, new Date(Date.now() + 86400000)); // cache config 24h
			return config;
		}
	}

	private async fetchOpenIdConfig(issuerUrl: string): Promise<IOpenIdConfig> {
		const issuerObj = new URL(issuerUrl);
		issuerObj.pathname = path.join(issuerObj.pathname, '/.well-known/openid-configuration');
		logger().debug(`jwt-util get JWT Configuration ${issuerObj.toString()}`);
		const req = new Request(issuerObj.toString());
		const res = await fetch(req);
		return this.isValidResp(res).json();
	}

	private isValidResp(resp: Response): Response {
		if (resp.status !== 200) {
			throw new Error('fetch error: ' + resp.statusText);
		}
		return resp;
	}
}
