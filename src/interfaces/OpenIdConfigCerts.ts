import type {JsonWebKey} from './JsonWebKey';

/**
 * OpenId Configuration Certificates.
 *
 * - [Json Web Key Spec](https://www.rfc-editor.org/rfc/rfc7517)
 * - [Google](https://www.googleapis.com/oauth2/v3/certs)
 * - [Azure](https://login.microsoftonline.com/common/discovery/v2.0/keys)
 */
export type OpenIdConfigCerts = {
	keys: JsonWebKey[];
};
