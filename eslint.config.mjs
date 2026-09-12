import js from "@eslint/js";
import ts from "typescript-eslint";
export default ts.config(
  {
    ignores: [
      "**/dist/**",
      "**/.next/**",
      "**/node_modules/**",
      // Python virtualenvs vendor their own JavaScript (werkzeug's debugger,
      // urllib3's emscripten worker). It is not this project's source.
      ".venv/**",
      "**/__pycache__/**",
      "**/next-env.d.ts",
      "test-results/**",
      "playwright-report/**",
      ".impeccable/**",
    ],
  },
  js.configs.recommended,
  ...ts.configs.recommended,
  {
    files: ["**/*.{ts,tsx,mjs,cjs}"],
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        fetch: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        document: "readonly",
        window: "readonly",
        navigator: "readonly",
        crypto: "readonly",
        exports: "writable",
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-namespace": ["error", { allowDeclarations: true }],
    },
  },
);
