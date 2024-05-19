import {z} from 'zod';

export function getError(error: unknown) {
	if (error instanceof Error) {
		return error;
	}
	if (typeof error === 'string') {
		return new Error(error);
	}
	return new TypeError(`Unknown error: ${JSON.stringify(error)}`);
}

export function assertZodError(error: unknown): asserts error is z.ZodError {
	if (!(error instanceof z.ZodError)) {
		throw getError(error);
	}
}
