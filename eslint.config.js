// ESLint v9+ flat config
import js from "@eslint/js";
import pluginHtml from "eslint-plugin-html";
import pluginImport from "eslint-plugin-import";
import pluginN from "eslint-plugin-n";
import pluginSecurity from "eslint-plugin-security";

export default [
  // Global ignores (replaces .eslintignore)
  { ignores: ["node_modules/**", "reports/**", "**/*bak*"] },

  js.configs.recommended,

  // JS files
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    languageOptions: { ecmaVersion: 2022, sourceType: "module" },
    plugins: { import: pluginImport, n: pluginN, security: pluginSecurity },
    rules: {
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      "no-undef": "error",
      "security/detect-object-injection": "off",
      "import/order": ["warn", { "newlines-between": "always" }],
    },
  },

  // HTML templates (parse only; no extra rules)
  {
    files: ["templates/**/*.html"],
    plugins: { html: pluginHtml },
  },
];
