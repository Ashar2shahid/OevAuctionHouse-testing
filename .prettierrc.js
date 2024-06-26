module.exports = {
  bracketSpacing: true,
  printWidth: 120,
  singleQuote: true,
  trailingComma: 'es5',
  useTabs: false,
  overrides: [
    {
      files: '*.md',
      options: {
        parser: 'markdown',
      },
    },
    {
      files: '*.sol',
      excludeFiles: 'contracts/test/AccessControlRegistry.sol',
      options: {
        compiler: '0.8.18',
        printWidth: 80,
        tabWidth: 4,
        useTabs: false,
        singleQuote: false,
        bracketSpacing: false,
      },
    },
    {
      files: 'contracts/test/AccessControlRegistry.sol',
      options: {
        compiler: '0.8.17',
        printWidth: 80,
        tabWidth: 4,
        useTabs: false,
        singleQuote: false,
        bracketSpacing: false,
      },
    },
  ],
};
