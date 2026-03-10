import { defineConfig } from '@playwright/test';
import path from 'path';

const extensionPath = path.resolve(__dirname);

export default defineConfig({
  testDir: './test',
  timeout: 60000,
  retries: 0,
  use: {
    headless: false,
  },
  projects: [
    {
      name: 'chromium-extension',
      use: {
        launchOptions: {
          args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`,
            '--no-first-run',
            '--disable-search-engine-choice-screen',
          ],
        },
      },
    },
  ],
});
