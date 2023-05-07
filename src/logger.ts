/* eslint-disable sort-keys, @typescript-eslint/no-empty-function */
import type {ILoggerLike} from '@avanio/logger-like';

const dummyLogger: ILoggerLike = {
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
};

let loggerFunction: ILoggerLike = dummyLogger;

export function setJwtLogger(newLogger: ILoggerLike) {
	loggerFunction = newLogger;
}

export function logger(): ILoggerLike {
	return loggerFunction;
}
