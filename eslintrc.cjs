module.exports = {
  extends: ["eslint:recommended"],
  env: { browser: true, es2021: true },
  plugins: ["html"],
  overrides: [{ files: ["templates/**/*.html"], processor: "html/html" }],
  rules: {
    "no-undef": "error",
    "no-unused-vars": "off",
    "no-console": "off"
  }
};
