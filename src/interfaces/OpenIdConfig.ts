import {z} from 'zod';

/**
 * OpenId Configuration validation schema.
 */
export const openIdConfigSchema = z.object({
	/**
	 * issuer identifier URL
	 * @example https://accounts.google.com
	 */
	issuer: z.string().url(),
	/**
	 * JWK certificate URL
	 *
	 * - [Google](https://www.googleapis.com/oauth2/v3/certs)
	 * - [Azure](https://login.microsoftonline.com/common/discovery/v2.0/keys)
	 */
	jwks_uri: z.string().url(),
});

/**
 * OpenId Configuration.
 *
 * - [OpenID Spec](https://openid.net/specs/openid-connect-discovery-1_0.html)
 * - [Azure](https://login.microsoftonline.com/common/.well-known/openid-configuration)
 * - [Google](https://accounts.google.com/.well-known/openid-configuration)
 */
export type OpenIdConfig = z.infer<typeof openIdConfigSchema>;
