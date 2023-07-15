import {ZodError, ZodIssue} from 'zod';

function formatZodIssue(issue: ZodIssue): string {
	const {path, message} = issue;
	const pathString = path.join('.');

	return `${pathString}: ${message}`;
}

// Format the Zod error message with only the current error
export function formatZodError(error: ZodError): Error {
	return new Error(error.issues.map(formatZodIssue).join('\n'));
}
