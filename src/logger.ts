import {LoggerLike} from './interfaces/loggerLike';

// tslint:disable: no-empty
const dummyLogger: LoggerLike = {
	debug: () => {},
	info: () => {},
	warn: () => {},
	error: () => {},
};

let loggerFunction: LoggerLike = dummyLogger;

export function setJwtLogger(newLogger: LoggerLike) {
	loggerFunction = newLogger;
}

export function logger(): LoggerLike {
	return loggerFunction;
}
