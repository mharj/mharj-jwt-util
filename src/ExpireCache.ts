export class ExpireCache<T extends object> {
	private cache: Record<string, {data: T, expires: number}> = {};
	public put(key: string, data: T, expires: number) {
		this.cache[key] = {data, expires};
	}
	public get(key: string) {
		this.cleanExpired();
		if (!this.cache[key]) {
			return undefined;
		}
		return this.cache[key].data;
	}
	public getCacheSize() {
		return Object.keys(this.cache).length;
	}
	private cleanExpired() {
		const now = new Date().getTime();
		Object.keys(this.cache).forEach((key) => {
			if (this.cache[key].expires < now) {
				delete this.cache[key];
			}
		});
	}
}
