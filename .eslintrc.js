// http://eslint.org/docs/user-guide/configuring

module.exports = {
  root: true,
  parserOptions: {
    sourceType: 'module'
  },
  env: {
    node: true
  },
  // https://github.com/feross/standard/blob/master/RULES.md#javascript-standard-style
  extends: [
    // add more generic rulesets here, such as:
    'eslint:recommended',
  ],
  // add your custom rules here
  'rules': {
    // allow paren-less arrow functions
    'arrow-parens': 0,
    // allow async-await
    'generator-star-spacing': 0,
    // allow debugger during development
    'no-debugger': process.env.NODE_ENV === 'production' ? 2 : 0,
    'quotes': ["error", "double"],
    "semi": [2, "always"],
    "space-before-function-paren": ["error", "never"],
    "brace-style": ["warn", "stroustrup"],
    "indent": ["error", 2, { "SwitchCase": 1 }],
    "no-console": 0
  }
}
