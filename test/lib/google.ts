import {type Credentials} from 'google-auth-library';
import {google} from 'googleapis';
import {z} from 'zod';

export function multilineEnvFix(input: string | undefined) {
	if (input === undefined) {
		return undefined;
	}
	return input.replace(/\\n/g, '\n');
}

async function getGoogleCredentials(): Promise<Credentials> {
	const clientKey = multilineEnvFix(process.env.GOOGLE_CLIENT_KEY);

	const jwtClient = new google.auth.JWT(
		process.env.GOOGLE_CLIENT_EMAIL,
		undefined,
		clientKey,
		['openid', 'https://www.googleapis.com/auth/cloud-platform'],
		undefined,
	);
	return jwtClient.authorize();
}

const parseJson = z.object({
	token: z.string(),
});

export async function getGoogleIdToken() {
	const body = JSON.stringify({
		audience: process.env.GOOGLE_CLIENT_EMAIL,
		delegates: [],
		includeEmail: true,
	});
	const headers = new Headers();
	headers.set('Authorization', 'Bearer ' + (await getGoogleCredentials()).access_token);
	headers.set('Content-Type', 'application/json');
	headers.set('Content-Length', '' + body.length);
	const res = await fetch(`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${process.env.GOOGLE_CLIENT_EMAIL}:generateIdToken`, {
		body,
		headers,
		method: 'POST',
	});
	if (res.status !== 200) {
		throw new Error('getGoogleIdToken code ' + res.status);
	}
	return parseJson.parse(await res.json()).token;
}
