/// <reference types="vitest" />

import {defineConfig} from 'vitest/config';

export default defineConfig({
	test: {
		reporters: ['github-actions', 'minimal'],
		coverage: {
			provider: 'v8',
			include: ['src/**/*.ts'],
			reporter: ['text', 'lcovonly'],
		},
		include: ['test/**/*.test.ts'],
		setupFiles: ['dotenv/config'],
	},
});
