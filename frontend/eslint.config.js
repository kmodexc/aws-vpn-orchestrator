import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.strictTypeChecked,
      reactHooks.configs.flat["recommended-latest"],
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // Security guard rails (CSP forbids inline styles; secrets never go into web storage).
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "dangerouslySetInnerHTML is forbidden.",
        },
        {
          selector: "JSXAttribute[name.name='style']",
          message: "Inline styles violate the CSP (style-src 'self'). Use a CSS class.",
        },
        {
          selector: "MemberExpression[property.name='innerHTML']",
          message: "innerHTML is forbidden.",
        },
      ],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Do not use web storage." },
        { name: "sessionStorage", message: "Do not use web storage." },
        { name: "eval", message: "eval is forbidden." },
      ],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
);
