import {z} from 'zod';

export const certItemSchema = z.object({
	alg: z.string().optional(),
	e: z.string(),
	issuer: z.string().optional(),
	kid: z.string(),
	kty: z.string(),
	n: z.string(),
	use: z.string(),
	x5c: z.array(z.string()).optional(),
	x5t: z.string().optional(),
});

export type ICertItem = z.infer<typeof certItemSchema>;
