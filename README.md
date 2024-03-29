# mharj-jwt-util

[![Build Status](https://mharj.visualstudio.com/mharj-jwt-util/_apis/build/status/mharj.mharj-jwt-util?branchName=master)](https://mharj.visualstudio.com/mharj-jwt-util/_build/latest?definitionId=3&branchName=master) ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/mharj/mharj-jwt-util/3) [![Maintainability](https://api.codeclimate.com/v1/badges/a60873c223b5bafadb1f/maintainability)](https://codeclimate.com/github/mharj/mharj-jwt-util/maintainability)

## Json Webtoken Utility to validate OpenID tokens against issuer public ssl keys

- Can build public PEM cert from modulus + exponent (i.e. Google)
- Caches issuer OpenID configuration 24h
- New Token "kid" forces reloading jwks_uri data.

Note: if running NodeJS less than 18.0.0 you need to install and use cross-fetch polyfill

## Usage example

```javascript
// with Bearer header
try {
	const {body, isCached} = await jwtBearerVerify(req.headers.authorization);
} catch (err) {
	console.log(err);
}
// or Just token
try {
	const {body, isCached} = await jwtVerify(process.env.GOOGLE_ID_TOKEN);
} catch (err) {
	console.log(err);
}

// attach logger to see http requests (console and log4js should be working)
setJwtLogger(console);
```

## Enable file caching

```javascript
await useCache(new FileCertCache({fileName: './certCache.json'}));

// or with Tachyon drive
await useCache(new TachyonCertCache(new FileStorageDriver('FileCertCacheDriver', './certCache.json', certCacheBufferSerializer)));
```

## Enable verified token persist caching (Tachyon drive with encryption)

```typescript
import {CacheMap, TachyonExpireCache} from 'tachyon-expire-cache';
import {CryptoBufferProcessor, FileStorageDriver} from 'tachyon-drive-node-fs';
import {IPersistSerializer} from 'tachyon-drive';

function cachePayloadSchema<T>(data: z.Schema<T>) {
	return z.object({
		data,
		expires: z.number().optional(),
	});
}
const anyObjectSchema = z.object({}).passthrough(); // or build token payload schema
const bufferSerializer: IPersistSerializer<CacheMap<TokenPayload, RawJwtToken>, Buffer> = {
	serialize: (data: CacheMap<TokenPayload, RawJwtToken>) => Buffer.from(JSON.stringify(Array.from(data))),
	deserialize: (buffer: Buffer) => new Map(JSON.parse(buffer.toString())),
	validator: (data: CacheMap<TokenPayload, RawJwtToken>) => z.map(z.string(), cachePayloadSchema(anyObjectSchema)).safeParse(data).success,
};
const processor = new CryptoBufferProcessor(Buffer.from('some-secret-key'));
const driver = new FileStorageDriver('TokenStorageDriver', './tokenCache.aes', bufferSerializer, processor);
const cache = new TachyonExpireCache<TokenPayload, RawJwtToken>(driver);

await setTokenCache(cache);
```
