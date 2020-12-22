import 'cross-fetch/polyfill';
import {posix as path} from 'path';
import {URL} from 'url';
import {logger} from './logger';
import {rsaPublicKeyPem} from './rsaPublicKeyPem';

interface IIssuerCerts {
	url: string;
	certs: ICertItem[];
}

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
interface IOpenIdConfig {
	jwks_uri: string;
}
interface IOpenIdConfigCache extends IOpenIdConfig {
	expires: number;
}
interface ICertList {
	keys: ICertItem[];
}
const configCache: {[key: string]: IOpenIdConfigCache} = {};
export class IssuerCertLoader {
	private certs: IIssuerCerts[] = [];

	public async getCert(issuerUrl: string, kid: string): Promise<Buffer | string> {
		const issuer = await this.getIssuerCerts(issuerUrl);
		const cert = await this.getIssuerCert(issuer, kid);
		return this.buildCert(cert);
	}

	public deleteKid(issuerUrl: string, kid: string): boolean {
		const issuer = this.certs.find((i) => i.url === issuerUrl);
		if (issuer) {
			const certIndex = issuer.certs.findIndex((c) => c.kid === kid);
			if (certIndex !== -1) {
				issuer.certs.splice(certIndex, 1);
				return true;
			}
		}
		return false;
	}

	public haveIssuer(issuerUrl: string) {
		return this.certs.find((i) => i.url === issuerUrl) ? true : false;
	}

	private async getIssuerCert(issuer: IIssuerCerts, kid: string) {
		let cert = issuer.certs.find((c) => c.kid === kid);
		if (!cert) {
			// we didn't find kid, reload all issuer certs
			issuer = await this.pullIssuerCerts(issuer.url);
		}
		cert = issuer.certs.find((c) => c.kid === kid);
		if (!cert) {
			// after issuer certs update, we still don't have cert for kid, throw out
			throw new Error(`no key Id '${kid}' found for issuer '${issuer.url}'`);
		}
		return cert;
	}

	private async getIssuerCerts(issuerUrl: string) {
		let issuer = this.certs.find((i) => i.url === issuerUrl);
		if (!issuer) {
			issuer = await this.pullIssuerCerts(issuerUrl);
		}
		/* istanbul ignore if  */
		if (!issuer) {
			throw new Error(`no '${issuer}' found!`);
		}
		return issuer;
	}

	private async pullIssuerCerts(issuerUrl: string) {
		const certList = await this.getCertList(issuerUrl);
		// store to certs array
		const issuer: IIssuerCerts = {
			url: issuerUrl,
			certs: certList.keys,
		};
		this.certs.push(issuer);
		return issuer;
	}

	private buildCert(cert: ICertItem): Promise<Buffer | string> {
		/* istanbul ignore else if  */
		if (cert.n && cert.e) {
			// we have modulo and exponent, build PEM
			cert.x5c = [rsaPublicKeyPem(cert.n, cert.e)];
			return Promise.resolve(Buffer.from(cert.x5c[0]));
		} else if (cert.x5c) {
			return Promise.resolve(Buffer.from(cert.x5c[0]));
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

	private getConfiguration(issuerUrl: string): Promise<IOpenIdConfig> {
		logger().debug(`jwt-util get JWT Configuration ${issuerUrl}`);
		const now = new Date().getDate();
		if (configCache[issuerUrl] && now < configCache[issuerUrl].expires) {
			return Promise.resolve(configCache[issuerUrl]);
		} else {
			const issuerObj = new URL(issuerUrl);
			issuerObj.pathname = path.join(issuerObj.pathname, '/.well-known/openid-configuration');
			const req = new Request(issuerObj.toString());
			return fetch(req)
				.then((resp) => this.isValidResp(resp).json())
				.then((config: IOpenIdConfig) => {
					configCache[issuerUrl] = {...config, expires: now + 86400000} as IOpenIdConfigCache; // cache config 24h
					return Promise.resolve(config);
				});
		}
	}

	private isValidResp(resp: Response): Response {
		if (resp.status !== 200) {
			throw new Error('fetch error: ' + resp.statusText);
		}
		return resp;
	}
}
