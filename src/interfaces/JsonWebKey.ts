import {z} from 'zod';

export const jsonWebKeySchema = z.object({
	/** algorithm for the public key */
	alg: z.string().optional(),
	/** public key exponent */
	e: z.string(),
	/** key issuer */
	issuer: z.string().optional(),
	/** key id */
	kid: z.string(),
	/** key type */
	kty: z.string(),
	/** public key modulus */
	n: z.string(),
	/** key usage */
	use: z.string(),
	/** x509 certificate chain */
	x5c: z.array(z.string()).optional(),
	/** x509 certificate thumbprint */
	x5t: z.string().optional(),
});

/**
 * Json Web Key validation schema.
 *
 * - [Json Web Key Spec](https://www.rfc-editor.org/rfc/rfc7517)
 */
export type JsonWebKey = z.infer<typeof jsonWebKeySchema>;
