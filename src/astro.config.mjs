// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
    output: 'static',
    // GitHub Pages 子路径；绑定自定义域名时改为 '/'
    // site: 'https://<user>.github.io',
    // base: '/cyber-daily-radar/',
    trailingSlash: 'ignore',
});
