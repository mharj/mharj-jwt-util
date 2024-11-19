export async function getAzureAccessToken() {
	// NOTE: Azure v2.0 accessToken is not atm valid JWT token (https://github.com/microsoft/azure-spring-boot/issues/476)
	const body = `client_id=${process.env.AZ_CLIENT_ID}&client_secret=${process.env.AZ_CLIENT_SECRET}&grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default`;
	const headers = new Headers();
	headers.set('Content-Type', 'application/x-www-form-urlencoded');
	headers.set('Content-Length', '' + body.length);
	const res = await fetch(`https://login.microsoftonline.com/${process.env.AZ_TENANT_ID}/oauth2/token`, {method: 'POST', headers, body});
	if (res.status !== 200) {
		throw new Error('getAzureAccessToken code ' + res.status);
	}
	const data = await res.json();
	return data.access_token;
}
