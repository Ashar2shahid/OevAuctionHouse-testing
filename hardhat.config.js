require('@nomicfoundation/hardhat-toolbox');
require('solidity-coverage');

module.exports = {
  solidity: {
    compilers: [
      {
        version: '0.8.17',
      },
      {
        version: '0.8.18',
        settings: {
          optimizer: {
            enabled: true,
            runs: 1000,
          },
        },
      },
    ],
  },
};
