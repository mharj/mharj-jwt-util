# mharj-jwt-util

[![Build Status](https://mharj.visualstudio.com/mharj-jwt-util/_apis/build/status/mharj.mharj-jwt-util?branchName=master)](https://mharj.visualstudio.com/mharj-jwt-util/_build/latest?definitionId=3&branchName=master) ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/mharj/mharj-jwt-util/3) [![Maintainability](https://api.codeclimate.com/v1/badges/a60873c223b5bafadb1f/maintainability)](https://codeclimate.com/github/mharj/mharj-jwt-util/maintainability)

## Json Webtoken Utility to validate OpenID tokens against issuer public ssl keys

- Can build public PEM cert from modulus + exponent (i.e. Google)
- Utilizes cross-fetch polyfill for loading issuer discovery configuration and "jwks_uri" data, so should work on most of JS platforms
- Caches issuer OpenID configuration 24h
- New Token "kid" forces reloading jwks_uri data.

## Usage example

```javascript
// with async
try {
	const decoded = await jwtBearerVerify(req.headers.authorization);
} catch (err) {
	console.log(err);
}
// or Promised
jwtBearerVerify(req.headers.authorization)
	.then((decoded) => {
		// do something
	})
	.catch((err) => {
		console.log(err);
	});
// or Just token
try {
	const decode = await jwtVerify(process.env.GOOGLE_ID_TOKEN);
} catch (err) {
	console.log(err);
}

// or Promised token
jwtVerify(process.env.GOOGLE_ID_TOKEN)
	.then((decoded) => {
		// do something
	})
	.catch((err) => {
		console.log(err);
	});

// attach logger to see http requests (console and log4js should be working)
setJwtLogger(console);
```
