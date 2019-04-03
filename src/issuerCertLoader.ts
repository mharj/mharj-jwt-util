import 'cross-fetch/polyfill';
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
		let issuer = this.certs.find((i) => i.url === issuerUrl);
		// if we don't have issuer yet loaded, or kid can't be found from list .. load cert list for issuer
		if (!issuer || !issuer.certs.find((c) => c.kid === kid)) {
			const certList = await this.getCertList(issuerUrl);
			if ( issuer ) { // we just update keys
				issuer.certs = certList.keys;
			} else {
				this.certs.push({url: issuerUrl, certs: certList.keys});
			}
		}
		issuer = this.certs.find((i) => i.url === issuerUrl);
		if (!issuer) {
			throw new Error('something strange - still no issuer found!');
		}
		const cert = issuer.certs.find((c) => c.kid === kid);
		if (cert) {
			if (cert.x5c) {
				return Promise.resolve(Buffer.from(cert.x5c[0]));
			} else {
				// we have only modulo and exponent, build PEM
				cert.x5c = [rsaPublicKeyPem(cert.n, cert.e)];
				return Promise.resolve(Buffer.from(cert.x5c[0]));
			}
		} else {
			throw new Error('no cert found');
		}
	}
	public deleteKid(issuerUrl: string, kid: string): boolean {
		const issuer = this.certs.find((i) => i.url === issuerUrl);
		if (issuer) {
			const certIndex = issuer.certs.findIndex((c) => c.kid === kid);
			if ( certIndex !== -1  ) {
				issuer.certs.splice(certIndex, 1);
				return true;
			}
		}
		return false;
	}
	private async getCertList(issuerUrl: string): Promise<ICertList> {
		const config = await this.getConfiguration(issuerUrl);
		return fetch(config.jwks_uri).then((resp) => resp.json());
	}
	private getConfiguration(issuerUrl: string): Promise<IOpenIdConfig> {
		const now = new Date().getDate();
		if (configCache[issuerUrl] && now < configCache[issuerUrl].expires) {
			return Promise.resolve(configCache[issuerUrl]);
		} else {
			const configUrl = issuerUrl + '/.well-known/openid-configuration';
			return fetch(configUrl)
				.then((resp) => resp.json())
				.then((config: IOpenIdConfig) => {
					configCache[issuerUrl] = {...config, expires: now + 86400000} as IOpenIdConfigCache; // cache config 24h
					return Promise.resolve(config);
				});
		}
	}
}
