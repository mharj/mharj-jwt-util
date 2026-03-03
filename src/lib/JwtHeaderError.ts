export class JwtHeaderError extends Error {
	public constructor(message: string) {
		super(message);
		this.name = 'JwtHeaderError';
		Error.captureStackTrace(this, this.constructor);
	}
}
