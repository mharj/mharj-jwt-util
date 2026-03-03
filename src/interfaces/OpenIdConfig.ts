/**
 * OpenId Configuration.
 *
 * - [OpenID Spec](https://openid.net/specs/openid-connect-discovery-1_0.html)
 * - [Azure](https://login.microsoftonline.com/common/.well-known/openid-configuration)
 * - [Google](https://accounts.google.com/.well-known/openid-configuration)
 */
export type OpenIdConfig = {
	issuer: string;
	jwks_uri: string;
};
