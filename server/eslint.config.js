import { defineConfig } from 'eslint/config';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import parser from '@typescript-eslint/parser';
import prettierPlugin from 'eslint-plugin-prettier';

const tsRecommended = tsPlugin.configs?.recommended ?? {};

export default defineConfig([
  {
    ignores: ['node_modules/**', 'dist/**', 'build/**', 'eslint.config.js'],
  },
  // TypeScript files: use parser with project to enable type-aware rules
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser,
      parserOptions: {
        project: ['./tsconfig.json'],
        tsconfigRootDir: new URL('.', import.meta.url).pathname,
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      prettier: prettierPlugin,
    },
    rules: {
      ...(tsRecommended.rules ?? {}),
      'prettier/prettier': 'error',
    },
    settings: {
      ...(tsRecommended.settings ?? {}),
    },
  },
  // JavaScript files: don't use type-aware parserOptions.project
  {
    files: ['**/*.js'],
    plugins: {
      prettier: prettierPlugin,
    },
    rules: {
      'prettier/prettier': 'error',
    },
  },
]);
