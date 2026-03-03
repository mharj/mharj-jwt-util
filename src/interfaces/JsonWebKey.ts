/**
 * Json Web Key validation schema.
 *
 * - [Json Web Key Spec](https://www.rfc-editor.org/rfc/rfc7517)
 */
export type JsonWebKey = {
	e: string;
	kid: string;
	kty: string;
	n: string;
	use: string;
	alg?: string | undefined;
	issuer?: string | undefined;
	x5c?: string[] | undefined;
	x5t?: string | undefined;
};
