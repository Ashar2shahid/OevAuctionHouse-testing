const { ethers } = require('hardhat');
const { expect } = require('chai');
const helpers = require('@nomicfoundation/hardhat-network-helpers');
const ethCrypto = require('eth-crypto');

describe('OevAuctionHouse', function () {
  const BidConditionType = Object.freeze(
    ['LTE', 'GTE'].reduce((acc, bidConditionTypeName, ind) => {
      return { ...acc, [bidConditionTypeName]: ind };
    }, {})
  );

  const BidStatus = Object.freeze(
    ['None', 'Placed', 'Awarded', 'FulfillmentReported', 'FulfillmentConfirmed', 'FulfillmentContradicted'].reduce(
      (acc, bidStatusName, ind) => {
        return { ...acc, [bidStatusName]: ind };
      },
      {}
    )
  );

  const PROXY_SETTER_ROLE_DESCRIPTION = 'Proxy setter';
  const WITHDRAWER_ROLE_DESCRIPTION = 'Withdrawer';
  const AUCTIONEER_ROLE_DESCRIPTION = 'Auctioneer';
  const WITHDRAWAL_WAITING_PERIOD = 15; // 15 seconds
  const MAXIMUM_BID_LIFETIME = 24 * 60 * 60; // 1 day
  const MINIMUM_BID_LIFETIME = 15; // 15 seconds
  const FULFILLMENT_REPORTING_PERIOD = 24 * 60 * 60; // 1 day
  // The encoded bid details from `encodeBidDetails()` below is 305 bytes
  // A transaction hash is 32 bytes
  const MAXIMUM_BIDDER_DATA_LENGTH = 1024;
  // `Api3ServerV1.updateOevProxyDataFeedWithSignedData()` calldata for
  // a Beacon set of 21 Beacons is 6336 bytes
  const MAXIMUM_AUCTIONEER_DATA_LENGTH = 8192;

  const HUNDRED_PERCENT_IN_BASIS_POINTS = 100 * 100;
  const MAXIMUM_RATE_AGE = 24 * 60 * 60; // 1 day

  // Below are example values
  const COLLATERAL_AMOUNT_IN_BASIS_POINTS = 7.5 * 100; // 7.5%
  const PROTOCOL_FEE_IN_BASIS_POINTS = 5 * 100; // 5%
  const CHAIN_ID_TO_PRICE = {
    1: ethers.utils.parseEther('1820'), // ETH/USD is 1,820
    97: ethers.utils.parseEther('230'), // BNB/USD is 230
    137: ethers.utils.parseEther('0.65'), // MATIC/USD is 0.65
  };
  const COLLATERAL_RATE = CHAIN_ID_TO_PRICE['1']; // Using ETH as collateral

  function deriveRootRole(managerAddress) {
    return ethers.utils.solidityKeccak256(['address'], [managerAddress]);
  }

  function deriveRole(adminRole, roleDescription) {
    return ethers.utils.solidityKeccak256(
      ['bytes32', 'bytes32'],
      [adminRole, ethers.utils.solidityKeccak256(['string'], [roleDescription])]
    );
  }

  // This is implemented as an example and is not necessarily the scheme that an auctioneer has to use.
  // Chain ID and bid amount are already provided in `placeBid()` so they do not need to duplicated here.
  // A salt field is added to support bids that would have an identical ID otherwise. The searcher should
  // use a salt that was never used before, and a random bytes32 would work fine here.
  // This function also includes a toy example for how bid details can be encrypted.
  async function encodeBidDetails(proxyWithOevAddress, conditionType, conditionValue, updateSenderAddress) {
    const bidDetails = ethers.utils.defaultAbiCoder.encode(
      ['address', 'uint256', 'int224', 'address', 'bytes32'],
      [
        proxyWithOevAddress,
        conditionType,
        conditionValue,
        updateSenderAddress,
        ethers.utils.hexlify(ethers.utils.randomBytes(32)),
      ]
    );
    // The auctioneer public key is provided in the searcher-facing documentation
    const auctioneerPublicKey =
      '046b3b7d231a75ff99f45ea3aa2b3b765c3f97857d1ecd904ae6cf165e75aa2086737de060e5ad916a6dfaa6506666bd44fae9fccdb67e6fdaccf8dfb48f95fbce';
    // The searcher does the following to encrypt the bid details with the auctioneer public key
    const encodedBidDetails = ethCrypto.hex.compress(bidDetails.substring(2), true);
    const encryptedBidDetails = ethCrypto.cipher.stringify(
      await ethCrypto.encryptWithPublicKey(auctioneerPublicKey, encodedBidDetails)
    );
    // Let us also demonstrate how the message is decrypted even though it is not needed for the purposes of this function.
    // Only the auctioneer bot knows its private key.
    const auctioneerPrivateKey = '0xf907099c3022166254c3d48ad51d8297a920670e8785a83a713e998137d1d585';
    const decryptedBidDetails = ethCrypto.hex.decompress(
      await ethCrypto.decryptWithPrivateKey(auctioneerPrivateKey, ethCrypto.cipher.parse(encryptedBidDetails)),
      true
    );
    if (decryptedBidDetails !== bidDetails) {
      throw new Error('Bid detail encryption example failed');
    }
    return `0x${encryptedBidDetails}`;
  }

  function deriveBidId(bidderAddress, bidTopic, bidDetails) {
    return ethers.utils.solidityKeccak256(
      ['address', 'bytes32', 'bytes32'],
      [bidderAddress, bidTopic, ethers.utils.keccak256(bidDetails)]
    );
  }

  function calculateCollateralAndProtocolFeeAmounts(chainId, bidAmount) {
    return {
      collateralAmount: bidAmount
        .mul(CHAIN_ID_TO_PRICE[chainId])
        .mul(COLLATERAL_AMOUNT_IN_BASIS_POINTS)
        .div(COLLATERAL_RATE)
        .div(HUNDRED_PERCENT_IN_BASIS_POINTS),
      protocolFeeAmount: bidAmount
        .mul(CHAIN_ID_TO_PRICE[chainId])
        .mul(PROTOCOL_FEE_IN_BASIS_POINTS)
        .div(COLLATERAL_RATE)
        .div(HUNDRED_PERCENT_IN_BASIS_POINTS),
    };
  }

  async function deploy() {
    const adminRoleDescription = 'OevAuctionHouse admin';

    const roleNames = ['deployer', 'manager', 'proxySetter', 'withdrawer', 'auctioneer', 'bidder', 'randomPerson'];
    const accounts = await ethers.getSigners();
    const roles = roleNames.reduce((acc, roleName, index) => {
      return { ...acc, [roleName]: accounts[index] };
    }, {});

    const AccessControlRegistry = await ethers.getContractFactory('AccessControlRegistry', roles.deployer);
    const accessControlRegistry = await AccessControlRegistry.deploy();

    const OevAuctionHouse = await ethers.getContractFactory('OevAuctionHouse', roles.deployer);
    const oevAuctionHouse = await OevAuctionHouse.deploy(
      accessControlRegistry.address,
      adminRoleDescription,
      roles.manager.address
    );

    const managerRootRole = deriveRootRole(roles.manager.address);
    const adminRole = deriveRole(managerRootRole, adminRoleDescription);
    await accessControlRegistry
      .connect(roles.manager)
      .initializeRoleAndGrantToSender(managerRootRole, adminRoleDescription);
    const proxySetterRole = deriveRole(adminRole, PROXY_SETTER_ROLE_DESCRIPTION);
    await accessControlRegistry
      .connect(roles.manager)
      .initializeRoleAndGrantToSender(adminRole, PROXY_SETTER_ROLE_DESCRIPTION);
    await accessControlRegistry.connect(roles.manager).grantRole(proxySetterRole, roles.proxySetter.address);
    const withdrawerRole = deriveRole(adminRole, WITHDRAWER_ROLE_DESCRIPTION);
    await accessControlRegistry
      .connect(roles.manager)
      .initializeRoleAndGrantToSender(adminRole, WITHDRAWER_ROLE_DESCRIPTION);
    await accessControlRegistry.connect(roles.manager).grantRole(withdrawerRole, roles.withdrawer.address);
    const auctioneerRole = deriveRole(adminRole, AUCTIONEER_ROLE_DESCRIPTION);
    await accessControlRegistry
      .connect(roles.manager)
      .initializeRoleAndGrantToSender(adminRole, AUCTIONEER_ROLE_DESCRIPTION);
    await accessControlRegistry.connect(roles.manager).grantRole(auctioneerRole, roles.auctioneer.address);

    const mockApi3ServerV1Address = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
    const MockProxy = await ethers.getContractFactory('MockProxy', roles.deployer);
    const collateralRateProxy = await MockProxy.deploy(mockApi3ServerV1Address);
    await collateralRateProxy.mock(COLLATERAL_RATE, Math.floor(Date.now() / 1000));
    const chainIdToNativeCurrencyRateProxy = await Object.keys(CHAIN_ID_TO_PRICE).reduce(async (acc, chainId) => {
      const proxy = await MockProxy.deploy(mockApi3ServerV1Address);
      await proxy.mock(CHAIN_ID_TO_PRICE[chainId], Math.floor(Date.now() / 1000));
      return { ...(await acc), [chainId]: proxy };
    }, Promise.resolve({}));

    return {
      roles,
      oevAuctionHouse,
      proxySetterRole,
      withdrawerRole,
      auctioneerRole,
      collateralRateProxy,
      chainIdToNativeCurrencyRateProxy,
    };
  }

  async function deployAndSetUp() {
    const deployment = await deploy();
    const { roles, oevAuctionHouse, collateralRateProxy, chainIdToNativeCurrencyRateProxy } = deployment;
    await oevAuctionHouse.connect(roles.manager).setCollateralInBasisPoints(COLLATERAL_AMOUNT_IN_BASIS_POINTS);
    await oevAuctionHouse.connect(roles.manager).setProtocolFeeInBasisPoints(PROTOCOL_FEE_IN_BASIS_POINTS);
    await oevAuctionHouse.connect(roles.manager).setCollateralRateProxy(collateralRateProxy.address);
    await Promise.all(
      Object.entries(chainIdToNativeCurrencyRateProxy).map(async ([chainId, nativeCurrencyRateProxy]) => {
        await oevAuctionHouse
          .connect(roles.manager)
          .setChainNativeCurrencyRateProxy(chainId, nativeCurrencyRateProxy.address);
      })
    );
    return deployment;
  }

  async function deployAndSetUpAndPlaceBid() {
    const deployment = await deployAndSetUp();
    const { roles, oevAuctionHouse } = deployment;
    const chainId = '137';
    const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
    const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
    const bidAmount = ethers.utils.parseEther('5');
    const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
    const bidDetails = await encodeBidDetails(
      proxyWithOevAddress,
      BidConditionType.GTE,
      ethers.utils.parseEther('2000'),
      updateSenderAddress
    );
    const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(chainId, bidAmount);
    const expirationTimestamp = (await helpers.time.latest()) + 60 * 60;
    const bidId = deriveBidId(roles.bidder.address, bidTopic, bidDetails);
    await oevAuctionHouse
      .connect(roles.bidder)
      .placeBidWithExpiration(
        bidTopic,
        chainId,
        bidAmount,
        bidDetails,
        collateralAmount,
        protocolFeeAmount,
        expirationTimestamp
      );
    return {
      ...deployment,
      bidParameters: {
        bidderAddress: roles.bidder.address,
        bidTopic,
        bidId,
        chainId,
        bidAmount,
        bidDetails,
        expirationTimestamp,
        collateralAmount,
        protocolFeeAmount,
      },
    };
  }

  async function deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmount() {
    const deployment = await deployAndSetUp();
    const { roles, oevAuctionHouse } = deployment;
    await oevAuctionHouse
      .connect(roles.manager)
      .setProtocolFeeInBasisPoints(COLLATERAL_AMOUNT_IN_BASIS_POINTS + 2.5 * 100);
    const chainId = '137';
    const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
    const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
    const bidAmount = ethers.utils.parseEther('5');
    const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
    const bidDetails = await encodeBidDetails(
      proxyWithOevAddress,
      BidConditionType.GTE,
      ethers.utils.parseEther('2000'),
      updateSenderAddress
    );
    const { collateralAmount, protocolFeeAmount } = await oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(
      chainId,
      bidAmount
    );
    const expirationTimestamp = (await helpers.time.latest()) + 60 * 60;
    const bidId = deriveBidId(roles.bidder.address, bidTopic, bidDetails);
    await oevAuctionHouse
      .connect(roles.bidder)
      .placeBidWithExpiration(
        bidTopic,
        chainId,
        bidAmount,
        bidDetails,
        collateralAmount,
        protocolFeeAmount,
        expirationTimestamp
      );
    return {
      ...deployment,
      bidParameters: {
        bidderAddress: roles.bidder.address,
        bidTopic,
        bidId,
        chainId,
        bidAmount,
        bidDetails,
        expirationTimestamp,
        collateralAmount,
        protocolFeeAmount,
      },
    };
  }

  async function deployAndSetUpAndPlaceBidAndAwardBid() {
    const deployment = await deployAndSetUpAndPlaceBid();
    const { roles, oevAuctionHouse, bidParameters } = deployment;
    const totalBidderDeposit = bidParameters.collateralAmount.add(bidParameters.protocolFeeAmount).mul(4);
    await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
    // The below is given as a placeholder, and the auctioneer can use any arbitrary award schema
    const awardDetails = ethers.utils.solidityPack(
      ['string'],
      ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
    );
    await oevAuctionHouse
      .connect(roles.auctioneer)
      .awardBid(
        bidParameters.bidderAddress,
        bidParameters.bidTopic,
        ethers.utils.keccak256(bidParameters.bidDetails),
        awardDetails,
        (await helpers.time.latest()) + 60
      );
    return deployment;
  }

  async function deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmountAndAwardBid() {
    const deployment = await deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmount();
    const { roles, oevAuctionHouse, bidParameters } = deployment;
    const totalBidderDeposit = bidParameters.collateralAmount.add(bidParameters.protocolFeeAmount).mul(4);
    await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
    // The below is given as a placeholder, and the auctioneer can use any arbitrary award schema
    const awardDetails = ethers.utils.solidityPack(
      ['string'],
      ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
    );
    await oevAuctionHouse
      .connect(roles.auctioneer)
      .awardBid(
        bidParameters.bidderAddress,
        bidParameters.bidTopic,
        ethers.utils.keccak256(bidParameters.bidDetails),
        awardDetails,
        (await helpers.time.latest()) + 60
      );
    return deployment;
  }

  async function deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment() {
    const deployment = await deployAndSetUpAndPlaceBidAndAwardBid();
    const { roles, oevAuctionHouse, bidParameters } = deployment;
    // The below is given as a placeholder, and the auctioneer can require any arbitrary fulfillment report schema
    const fulfillmentDetails = ethers.utils.defaultAbiCoder.encode(['string'], ['Hash of the OEV update transaction']);
    await oevAuctionHouse
      .connect(roles.bidder)
      .reportFulfillment(bidParameters.bidTopic, ethers.utils.keccak256(bidParameters.bidDetails), fulfillmentDetails);
    return deployment;
  }

  async function deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmountAndAwardBidAndReportFulfillment() {
    const deployment = await deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmountAndAwardBid();
    const { roles, oevAuctionHouse, bidParameters } = deployment;
    // The below is given as a placeholder, and the auctioneer can require any arbitrary fulfillment report schema
    const fulfillmentDetails = ethers.utils.defaultAbiCoder.encode(['string'], ['Hash of the OEV update transaction']);
    await oevAuctionHouse
      .connect(roles.bidder)
      .reportFulfillment(bidParameters.bidTopic, ethers.utils.keccak256(bidParameters.bidDetails), fulfillmentDetails);
    return deployment;
  }

  async function deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment() {
    const deployment = await deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment();
    const { roles, oevAuctionHouse, bidParameters } = deployment;
    await oevAuctionHouse
      .connect(roles.auctioneer)
      .contradictFulfillment(
        bidParameters.bidderAddress,
        bidParameters.bidTopic,
        ethers.utils.keccak256(bidParameters.bidDetails)
      );
    return deployment;
  }

  async function deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment() {
    const deployment = await deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment();
    const { roles, oevAuctionHouse, bidParameters } = deployment;
    await oevAuctionHouse
      .connect(roles.auctioneer)
      .confirmFulfillment(
        bidParameters.bidderAddress,
        bidParameters.bidTopic,
        ethers.utils.keccak256(bidParameters.bidDetails)
      );
    return deployment;
  }

  describe('constructor', function () {
    it('constructs', async function () {
      const { oevAuctionHouse, proxySetterRole, withdrawerRole, auctioneerRole } = await helpers.loadFixture(deploy);
      expect(await oevAuctionHouse.PROXY_SETTER_ROLE_DESCRIPTION()).to.be.equal(PROXY_SETTER_ROLE_DESCRIPTION);
      expect(await oevAuctionHouse.WITHDRAWER_ROLE_DESCRIPTION()).to.be.equal(WITHDRAWER_ROLE_DESCRIPTION);
      expect(await oevAuctionHouse.AUCTIONEER_ROLE_DESCRIPTION()).to.be.equal(AUCTIONEER_ROLE_DESCRIPTION);
      expect(await oevAuctionHouse.WITHDRAWAL_WAITING_PERIOD()).to.be.equal(WITHDRAWAL_WAITING_PERIOD);
      expect(await oevAuctionHouse.MAXIMUM_BID_LIFETIME()).to.be.equal(MAXIMUM_BID_LIFETIME);
      expect(await oevAuctionHouse.MINIMUM_BID_LIFETIME()).to.be.equal(MINIMUM_BID_LIFETIME);
      expect(await oevAuctionHouse.FULFILLMENT_REPORTING_PERIOD()).to.be.equal(FULFILLMENT_REPORTING_PERIOD);
      expect(await oevAuctionHouse.MAXIMUM_BIDDER_DATA_LENGTH()).to.be.equal(MAXIMUM_BIDDER_DATA_LENGTH);
      expect(await oevAuctionHouse.MAXIMUM_AUCTIONEER_DATA_LENGTH()).to.be.equal(MAXIMUM_AUCTIONEER_DATA_LENGTH);
      expect(await oevAuctionHouse.proxySetterRole()).to.be.equal(proxySetterRole);
      expect(await oevAuctionHouse.withdrawerRole()).to.be.equal(withdrawerRole);
      expect(await oevAuctionHouse.auctioneerRole()).to.be.equal(auctioneerRole);
    });
  });

  describe('setCollateralInBasisPoints', function () {
    context('Sender is the manager', function () {
      it('sets collateral requirement in basis points', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        expect(await oevAuctionHouse.collateralInBasisPoints()).to.equal(0);
        const collateralInBasisPoints = HUNDRED_PERCENT_IN_BASIS_POINTS + 1;
        await expect(oevAuctionHouse.connect(roles.manager).setCollateralInBasisPoints(collateralInBasisPoints))
          .to.emit(oevAuctionHouse, 'SetCollateralInBasisPoints')
          .withArgs(collateralInBasisPoints);
        expect(await oevAuctionHouse.collateralInBasisPoints()).to.equal(collateralInBasisPoints);
      });
    });
    context('Sender is not the manager', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        const collateralInBasisPoints = HUNDRED_PERCENT_IN_BASIS_POINTS + 1;
        await expect(oevAuctionHouse.connect(roles.randomPerson).setCollateralInBasisPoints(collateralInBasisPoints))
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotTheManager')
          .withArgs();
      });
    });
  });

  describe('setProtocolFeeInBasisPoints', function () {
    context('Sender is the manager', function () {
      it('sets protocol fee in basis points', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        expect(await oevAuctionHouse.protocolFeeInBasisPoints()).to.equal(0);
        const protocolFeeInBasisPoints = HUNDRED_PERCENT_IN_BASIS_POINTS + 1;
        await expect(oevAuctionHouse.connect(roles.manager).setProtocolFeeInBasisPoints(protocolFeeInBasisPoints))
          .to.emit(oevAuctionHouse, 'SetProtocolFeeInBasisPoints')
          .withArgs(protocolFeeInBasisPoints);
        expect(await oevAuctionHouse.protocolFeeInBasisPoints()).to.equal(protocolFeeInBasisPoints);
      });
    });
    context('Sender is not the manager', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        const protocolFeeInBasisPoints = HUNDRED_PERCENT_IN_BASIS_POINTS + 1;
        await expect(oevAuctionHouse.connect(roles.randomPerson).setProtocolFeeInBasisPoints(protocolFeeInBasisPoints))
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotTheManager')
          .withArgs();
      });
    });
  });

  describe('setCollateralRateProxy', function () {
    context('Sender is a proxy setter', function () {
      context('Collateral rate proxy address is not zero', function () {
        it('sets collateral rate proxy', async function () {
          const { roles, oevAuctionHouse, collateralRateProxy } = await helpers.loadFixture(deploy);
          expect(await oevAuctionHouse.collateralRateProxy()).to.equal(ethers.constants.AddressZero);
          await expect(oevAuctionHouse.connect(roles.proxySetter).setCollateralRateProxy(collateralRateProxy.address))
            .to.emit(oevAuctionHouse, 'SetCollateralRateProxy')
            .withArgs(collateralRateProxy.address);
          expect(await oevAuctionHouse.collateralRateProxy()).to.equal(collateralRateProxy.address);
        });
      });
      context('Collateral rate proxy address is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
          await expect(oevAuctionHouse.connect(roles.proxySetter).setCollateralRateProxy(ethers.constants.AddressZero))
            .to.be.revertedWithCustomError(oevAuctionHouse, 'ProxyAddressIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is the manager', function () {
      context('Collateral rate proxy address is not zero', function () {
        it('sets collateral rate proxy', async function () {
          const { roles, oevAuctionHouse, collateralRateProxy } = await helpers.loadFixture(deploy);
          expect(await oevAuctionHouse.collateralRateProxy()).to.equal(ethers.constants.AddressZero);
          await expect(oevAuctionHouse.connect(roles.manager).setCollateralRateProxy(collateralRateProxy.address))
            .to.emit(oevAuctionHouse, 'SetCollateralRateProxy')
            .withArgs(collateralRateProxy.address);
          expect(await oevAuctionHouse.collateralRateProxy()).to.equal(collateralRateProxy.address);
        });
      });
      context('Collateral rate proxy address is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
          await expect(oevAuctionHouse.connect(roles.manager).setCollateralRateProxy(ethers.constants.AddressZero))
            .to.be.revertedWithCustomError(oevAuctionHouse, 'ProxyAddressIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is not a proxy setter or the manager', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse, collateralRateProxy } = await helpers.loadFixture(deploy);
        await expect(oevAuctionHouse.connect(roles.randomPerson).setCollateralRateProxy(collateralRateProxy.address))
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAProxySetterOrTheManager')
          .withArgs();
      });
    });
  });

  describe('setChainNativeCurrencyRateProxy', function () {
    context('Sender is a proxy setter', function () {
      context('Chain ID is not zero', function () {
        context('Collateral rate proxy address is not zero', function () {
          it('sets collateral rate proxy', async function () {
            const { roles, oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(deploy);
            const chainId = 1;
            expect(await oevAuctionHouse.chainIdToNativeCurrencyRateProxy(chainId)).to.equal(
              ethers.constants.AddressZero
            );
            await expect(
              oevAuctionHouse
                .connect(roles.proxySetter)
                .setChainNativeCurrencyRateProxy(chainId, chainIdToNativeCurrencyRateProxy[chainId].address)
            )
              .to.emit(oevAuctionHouse, 'SetChainNativeCurrencyRateProxy')
              .withArgs(chainId, chainIdToNativeCurrencyRateProxy[chainId].address);
            expect(await oevAuctionHouse.chainIdToNativeCurrencyRateProxy(chainId)).to.equal(
              chainIdToNativeCurrencyRateProxy[chainId].address
            );
          });
        });
        context('Collateral rate proxy address is zero', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
            const chainId = 1;
            await expect(
              oevAuctionHouse
                .connect(roles.proxySetter)
                .setChainNativeCurrencyRateProxy(chainId, ethers.constants.AddressZero)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'ProxyAddressIsZero')
              .withArgs();
          });
        });
      });
      context('Chain ID is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(deploy);
          await expect(
            oevAuctionHouse
              .connect(roles.proxySetter)
              .setChainNativeCurrencyRateProxy(0, chainIdToNativeCurrencyRateProxy[1].address)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'ChainIdIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is the manager', function () {
      context('Chain ID is not zero', function () {
        context('Collateral rate proxy address is not zero', function () {
          it('sets collateral rate proxy', async function () {
            const { roles, oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(deploy);
            const chainId = 1;
            expect(await oevAuctionHouse.chainIdToNativeCurrencyRateProxy(chainId)).to.equal(
              ethers.constants.AddressZero
            );
            await expect(
              oevAuctionHouse
                .connect(roles.manager)
                .setChainNativeCurrencyRateProxy(chainId, chainIdToNativeCurrencyRateProxy[chainId].address)
            )
              .to.emit(oevAuctionHouse, 'SetChainNativeCurrencyRateProxy')
              .withArgs(chainId, chainIdToNativeCurrencyRateProxy[chainId].address);
            expect(await oevAuctionHouse.chainIdToNativeCurrencyRateProxy(chainId)).to.equal(
              chainIdToNativeCurrencyRateProxy[chainId].address
            );
          });
        });
        context('Collateral rate proxy address is zero', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
            const chainId = 1;
            await expect(
              oevAuctionHouse
                .connect(roles.manager)
                .setChainNativeCurrencyRateProxy(chainId, ethers.constants.AddressZero)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'ProxyAddressIsZero')
              .withArgs();
          });
        });
      });
      context('Chain ID is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(deploy);
          await expect(
            oevAuctionHouse
              .connect(roles.manager)
              .setChainNativeCurrencyRateProxy(0, chainIdToNativeCurrencyRateProxy[1].address)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'ChainIdIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is not a proxy setter or the manager', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(deploy);
        const chainId = 1;
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .setChainNativeCurrencyRateProxy(chainId, chainIdToNativeCurrencyRateProxy[chainId].address)
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAProxySetterOrTheManager')
          .withArgs();
      });
    });
  });

  describe('withdrawAccumulatedSlashedCollateral', function () {
    context('Sender is a withdrawer', function () {
      context('Recipient address is not zero', function () {
        context('Amount is not zero', function () {
          context('Amount does not exceed balance', function () {
            context('Transfer is successful', function () {
              it('withdraws accumulated slashed collateral', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
                );
                const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
                const expectedRecipientBalance = (await ethers.provider.getBalance(roles.randomPerson.address)).add(
                  accumulatedSlashedCollateral
                );
                await expect(
                  oevAuctionHouse
                    .connect(roles.withdrawer)
                    .withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, accumulatedSlashedCollateral)
                )
                  .to.emit(oevAuctionHouse, 'WithdrewAccumulatedSlashedCollateral')
                  .withArgs(roles.randomPerson.address, accumulatedSlashedCollateral);
                expect(await oevAuctionHouse.accumulatedSlashedCollateral()).to.equal(0);
                expect(await ethers.provider.getBalance(roles.randomPerson.address)).to.equal(expectedRecipientBalance);
              });
            });
            context('Transfer is not successful', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
                );
                const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
                await expect(
                  oevAuctionHouse
                    .connect(roles.withdrawer)
                    .withdrawAccumulatedSlashedCollateral(oevAuctionHouse.address, accumulatedSlashedCollateral)
                ).to.be.revertedWith('Transfer unsuccessful');
              });
            });
          });
          context('Amount exceeds balance', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(
                deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
              );
              const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
              await expect(
                oevAuctionHouse
                  .connect(roles.withdrawer)
                  .withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, accumulatedSlashedCollateral.add(1))
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'InsufficientBalance')
                .withArgs();
            });
          });
        });
        context('Amount is zero', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
            );
            await expect(
              oevAuctionHouse
                .connect(roles.withdrawer)
                .withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, 0)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'WithdrawalAmountIsZero')
              .withArgs();
          });
        });
      });
      context('Recipient address is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
          );
          const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
          await expect(
            oevAuctionHouse
              .connect(roles.withdrawer)
              .withdrawAccumulatedSlashedCollateral(ethers.constants.AddressZero, accumulatedSlashedCollateral)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'RecipientAddressIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is the manager', function () {
      context('Recipient address is not zero', function () {
        context('Amount is not zero', function () {
          context('Amount does not exceed balance', function () {
            context('Transfer is successful', function () {
              it('withdraws accumulated slashed collateral', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
                );
                const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
                const expectedRecipientBalance = (await ethers.provider.getBalance(roles.randomPerson.address)).add(
                  accumulatedSlashedCollateral
                );
                await expect(
                  oevAuctionHouse
                    .connect(roles.manager)
                    .withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, accumulatedSlashedCollateral)
                )
                  .to.emit(oevAuctionHouse, 'WithdrewAccumulatedSlashedCollateral')
                  .withArgs(roles.randomPerson.address, accumulatedSlashedCollateral);
                expect(await oevAuctionHouse.accumulatedSlashedCollateral()).to.equal(0);
                expect(await ethers.provider.getBalance(roles.randomPerson.address)).to.equal(expectedRecipientBalance);
              });
            });
            context('Transfer is not successful', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
                );
                const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
                await expect(
                  oevAuctionHouse
                    .connect(roles.manager)
                    .withdrawAccumulatedSlashedCollateral(oevAuctionHouse.address, accumulatedSlashedCollateral)
                ).to.be.revertedWith('Transfer unsuccessful');
              });
            });
          });
          context('Amount exceeds balance', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(
                deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
              );
              const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
              await expect(
                oevAuctionHouse
                  .connect(roles.manager)
                  .withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, accumulatedSlashedCollateral.add(1))
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'InsufficientBalance')
                .withArgs();
            });
          });
        });
        context('Amount is zero', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
            );
            await expect(
              oevAuctionHouse.connect(roles.manager).withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, 0)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'WithdrawalAmountIsZero')
              .withArgs();
          });
        });
      });
      context('Recipient address is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
          );
          const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
          await expect(
            oevAuctionHouse
              .connect(roles.manager)
              .withdrawAccumulatedSlashedCollateral(ethers.constants.AddressZero, accumulatedSlashedCollateral)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'RecipientAddressIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is not a withdrawer or the manager', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(
          deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndContradictFulfillment
        );
        const accumulatedSlashedCollateral = await oevAuctionHouse.accumulatedSlashedCollateral();
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .withdrawAccumulatedSlashedCollateral(roles.randomPerson.address, accumulatedSlashedCollateral)
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAWithdrawerOrTheManager')
          .withArgs();
      });
    });
  });

  describe('withdrawAccumulatedProtocolFees', function () {
    context('Sender is a withdrawer', function () {
      context('Recipient address is not zero', function () {
        context('Amount is not zero', function () {
          context('Amount does not exceed balance', function () {
            context('Transfer is successful', function () {
              it('withdraws accumulated protocol fees', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
                );
                const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
                const expectedRecipientBalance = (await ethers.provider.getBalance(roles.randomPerson.address)).add(
                  accumulatedProtocolFees
                );
                await expect(
                  oevAuctionHouse
                    .connect(roles.withdrawer)
                    .withdrawAccumulatedProtocolFees(roles.randomPerson.address, accumulatedProtocolFees)
                )
                  .to.emit(oevAuctionHouse, 'WithdrewAccumulatedProtocolFees')
                  .withArgs(roles.randomPerson.address, accumulatedProtocolFees);
                expect(await oevAuctionHouse.accumulatedProtocolFees()).to.equal(0);
                expect(await ethers.provider.getBalance(roles.randomPerson.address)).to.equal(expectedRecipientBalance);
              });
            });
            context('Transfer is not successful', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
                );
                const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
                await expect(
                  oevAuctionHouse
                    .connect(roles.withdrawer)
                    .withdrawAccumulatedProtocolFees(oevAuctionHouse.address, accumulatedProtocolFees)
                ).to.be.revertedWith('Transfer unsuccessful');
              });
            });
          });
          context('Amount exceeds balance', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(
                deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
              );
              const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
              await expect(
                oevAuctionHouse
                  .connect(roles.withdrawer)
                  .withdrawAccumulatedProtocolFees(roles.randomPerson.address, accumulatedProtocolFees.add(1))
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'InsufficientBalance')
                .withArgs();
            });
          });
        });
        context('Amount is zero', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
            );
            await expect(
              oevAuctionHouse.connect(roles.withdrawer).withdrawAccumulatedProtocolFees(roles.randomPerson.address, 0)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'WithdrawalAmountIsZero')
              .withArgs();
          });
        });
      });
      context('Recipient address is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
          );
          const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
          await expect(
            oevAuctionHouse
              .connect(roles.withdrawer)
              .withdrawAccumulatedProtocolFees(ethers.constants.AddressZero, accumulatedProtocolFees)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'RecipientAddressIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is the manager', function () {
      context('Recipient address is not zero', function () {
        context('Amount is not zero', function () {
          context('Amount does not exceed balance', function () {
            context('Transfer is successful', function () {
              it('withdraws accumulated protocol fees', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
                );
                const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
                const expectedRecipientBalance = (await ethers.provider.getBalance(roles.randomPerson.address)).add(
                  accumulatedProtocolFees
                );
                await expect(
                  oevAuctionHouse
                    .connect(roles.manager)
                    .withdrawAccumulatedProtocolFees(roles.randomPerson.address, accumulatedProtocolFees)
                )
                  .to.emit(oevAuctionHouse, 'WithdrewAccumulatedProtocolFees')
                  .withArgs(roles.randomPerson.address, accumulatedProtocolFees);
                expect(await oevAuctionHouse.accumulatedProtocolFees()).to.equal(0);
                expect(await ethers.provider.getBalance(roles.randomPerson.address)).to.equal(expectedRecipientBalance);
              });
            });
            context('Transfer is not successful', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(
                  deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
                );
                const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
                await expect(
                  oevAuctionHouse
                    .connect(roles.manager)
                    .withdrawAccumulatedProtocolFees(oevAuctionHouse.address, accumulatedProtocolFees)
                ).to.be.revertedWith('Transfer unsuccessful');
              });
            });
          });
          context('Amount exceeds balance', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(
                deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
              );
              const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
              await expect(
                oevAuctionHouse
                  .connect(roles.manager)
                  .withdrawAccumulatedProtocolFees(roles.randomPerson.address, accumulatedProtocolFees.add(1))
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'InsufficientBalance')
                .withArgs();
            });
          });
        });
        context('Amount is zero', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
            );
            await expect(
              oevAuctionHouse.connect(roles.manager).withdrawAccumulatedProtocolFees(roles.randomPerson.address, 0)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'WithdrawalAmountIsZero')
              .withArgs();
          });
        });
      });
      context('Recipient address is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
          );
          const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
          await expect(
            oevAuctionHouse
              .connect(roles.manager)
              .withdrawAccumulatedProtocolFees(ethers.constants.AddressZero, accumulatedProtocolFees)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'RecipientAddressIsZero')
            .withArgs();
        });
      });
    });
    context('Sender is not a withdrawer or the manager', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(
          deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillmentAndConfirmFulfillment
        );
        const accumulatedProtocolFees = await oevAuctionHouse.accumulatedProtocolFees();
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .withdrawAccumulatedProtocolFees(roles.randomPerson.address, accumulatedProtocolFees)
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAWithdrawerOrTheManager')
          .withArgs();
      });
    });
  });

  describe('depositForBidder', function () {
    context('Bidder address is not zero', function () {
      context('Deposit amount is not zero', function () {
        it('deposits for bidder', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
          const bidderDepositBefore = ethers.utils.parseEther('123');
          await oevAuctionHouse
            .connect(roles.randomPerson)
            .depositForBidder(roles.bidder.address, { value: bidderDepositBefore });
          expect(await oevAuctionHouse.bidderToBalance(roles.bidder.address)).to.equal(bidderDepositBefore);
          const depositAmount = ethers.utils.parseEther('1');
          const depositorBalanceBefore = await ethers.provider.getBalance(roles.randomPerson.address);
          const oevAuctionHouseBalanceBefore = await ethers.provider.getBalance(oevAuctionHouse.address);
          expect(
            await oevAuctionHouse
              .connect(roles.randomPerson)
              .callStatic.depositForBidder(roles.bidder.address, { value: depositAmount })
          ).to.equal(bidderDepositBefore.add(depositAmount));
          await expect(
            oevAuctionHouse.connect(roles.randomPerson).depositForBidder(roles.bidder.address, { value: depositAmount })
          )
            .to.emit(oevAuctionHouse, 'Deposited')
            .withArgs(
              roles.bidder.address,
              depositAmount,
              bidderDepositBefore.add(depositAmount),
              roles.randomPerson.address
            );
          expect(await oevAuctionHouse.bidderToBalance(roles.bidder.address)).to.equal(
            bidderDepositBefore.add(depositAmount)
          );
          expect(await ethers.provider.getBalance(roles.randomPerson.address)).to.lessThan(
            depositorBalanceBefore.sub(depositAmount)
          );
          expect(await ethers.provider.getBalance(oevAuctionHouse.address)).to.equal(
            oevAuctionHouseBalanceBefore.add(depositAmount)
          );
        });
      });
      context('Deposit amount is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
          await expect(oevAuctionHouse.connect(roles.randomPerson).depositForBidder(roles.bidder.address))
            .to.be.revertedWithCustomError(oevAuctionHouse, 'DepositAmountIsZero')
            .withArgs();
        });
      });
    });
    context('Bidder address is zero', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        const depositAmount = ethers.utils.parseEther('1');
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .depositForBidder(ethers.constants.AddressZero, { value: depositAmount })
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'BidderAddressIsZero')
          .withArgs();
      });
    });
  });

  describe('deposit', function () {
    context('Deposit amount is not zero', function () {
      it('deposits', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        const bidderDepositBefore = ethers.utils.parseEther('123');
        await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
        expect(await oevAuctionHouse.bidderToBalance(roles.bidder.address)).to.equal(bidderDepositBefore);
        const depositAmount = ethers.utils.parseEther('1');
        const depositorBalanceBefore = await ethers.provider.getBalance(roles.bidder.address);
        const oevAuctionHouseBalanceBefore = await ethers.provider.getBalance(oevAuctionHouse.address);
        expect(await oevAuctionHouse.connect(roles.bidder).callStatic.deposit({ value: depositAmount })).to.equal(
          bidderDepositBefore.add(depositAmount)
        );
        await expect(oevAuctionHouse.connect(roles.bidder).deposit({ value: depositAmount }))
          .to.emit(oevAuctionHouse, 'Deposited')
          .withArgs(roles.bidder.address, depositAmount, bidderDepositBefore.add(depositAmount), roles.bidder.address);
        expect(await oevAuctionHouse.bidderToBalance(roles.bidder.address)).to.equal(
          bidderDepositBefore.add(depositAmount)
        );
        expect(await ethers.provider.getBalance(roles.bidder.address)).to.lessThan(
          depositorBalanceBefore.sub(depositAmount)
        );
        expect(await ethers.provider.getBalance(oevAuctionHouse.address)).to.equal(
          oevAuctionHouseBalanceBefore.add(depositAmount)
        );
      });
    });
    context('Deposit amount is zero', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        await expect(oevAuctionHouse.connect(roles.bidder).deposit())
          .to.be.revertedWithCustomError(oevAuctionHouse, 'DepositAmountIsZero')
          .withArgs();
      });
    });
  });

  describe('initiateWithdrawal', function () {
    context('Bidder does not have an initiated withdrawal', function () {
      it('initiates withdrawal', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        const currentTimestamp = await helpers.time.latest();
        const nextTimestamp = currentTimestamp + 1;
        await helpers.time.setNextBlockTimestamp(nextTimestamp);
        const expectedEarliestWithdrawalTimestamp = nextTimestamp + WITHDRAWAL_WAITING_PERIOD;
        expect(await oevAuctionHouse.bidderToEarliestWithdrawalTimestamp(roles.bidder.address)).to.equal(0);
        expect(await oevAuctionHouse.connect(roles.bidder).callStatic.initiateWithdrawal()).to.equal(
          currentTimestamp + WITHDRAWAL_WAITING_PERIOD
        );
        await expect(oevAuctionHouse.connect(roles.bidder).initiateWithdrawal())
          .to.emit(oevAuctionHouse, 'InitiatedWithdrawal')
          .withArgs(roles.bidder.address, expectedEarliestWithdrawalTimestamp);
        expect(await oevAuctionHouse.bidderToEarliestWithdrawalTimestamp(roles.bidder.address)).to.equal(
          expectedEarliestWithdrawalTimestamp
        );
      });
    });
    context('Bidder has an initiated withdrawal', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
        await expect(oevAuctionHouse.connect(roles.bidder).initiateWithdrawal())
          .to.be.revertedWithCustomError(oevAuctionHouse, 'BidderHasAlreadyInitiatedWithdrawal')
          .withArgs();
      });
    });
  });

  describe('withdraw', function () {
    context('Recipient address is not zero', function () {
      context('Amount is not zero', function () {
        context('Amount does not exceed balance', function () {
          context('Sender has an initiated withdrawal', function () {
            context('It is time for the bidder to be able to withdraw', function () {
              context('Transfer is successful', function () {
                it('withdraws', async function () {
                  const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
                  const bidderDepositBefore = ethers.utils.parseEther('123');
                  await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
                  await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
                  await helpers.time.setNextBlockTimestamp((await helpers.time.latest()) + WITHDRAWAL_WAITING_PERIOD);
                  const recipientBalanceBefore = await ethers.provider.getBalance(roles.randomPerson.address);
                  const oevAuctionHouseBalanceBefore = await ethers.provider.getBalance(oevAuctionHouse.address);
                  await expect(
                    oevAuctionHouse.connect(roles.bidder).withdraw(roles.randomPerson.address, bidderDepositBefore)
                  )
                    .to.emit(oevAuctionHouse, 'Withdrew')
                    .withArgs(roles.bidder.address, roles.randomPerson.address, bidderDepositBefore);
                  expect(await oevAuctionHouse.bidderToBalance(roles.bidder.address)).to.equal(0);
                  expect(await oevAuctionHouse.bidderToEarliestWithdrawalTimestamp(roles.bidder.address)).to.equal(0);
                  expect(await ethers.provider.getBalance(roles.randomPerson.address)).to.equal(
                    recipientBalanceBefore.add(bidderDepositBefore)
                  );
                  expect(await ethers.provider.getBalance(oevAuctionHouse.address)).to.equal(
                    oevAuctionHouseBalanceBefore.sub(bidderDepositBefore)
                  );
                });
              });
              context('Transfer is not successful', function () {
                it('reverts', async function () {
                  const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
                  const bidderDepositBefore = ethers.utils.parseEther('123');
                  await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
                  await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
                  await helpers.time.setNextBlockTimestamp((await helpers.time.latest()) + WITHDRAWAL_WAITING_PERIOD);
                  await expect(
                    oevAuctionHouse.connect(roles.bidder).withdraw(oevAuctionHouse.address, bidderDepositBefore)
                  ).to.be.revertedWith('Transfer unsuccessful');
                });
              });
            });
            context('It is not time yet for the bidder to be able to withdraw', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
                const bidderDepositBefore = ethers.utils.parseEther('123');
                await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
                await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
                await helpers.time.setNextBlockTimestamp((await helpers.time.latest()) + WITHDRAWAL_WAITING_PERIOD - 1);
                await expect(oevAuctionHouse.connect(roles.bidder).withdraw(roles.bidder.address, bidderDepositBefore))
                  .to.be.revertedWithCustomError(oevAuctionHouse, 'BidderCannotWithdrawYet')
                  .withArgs();
              });
            });
          });
          context('Sender does not have an initiated withdrawal', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
              const bidderDepositBefore = ethers.utils.parseEther('123');
              await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
              await expect(oevAuctionHouse.connect(roles.bidder).withdraw(roles.bidder.address, bidderDepositBefore))
                .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderHasNotInitiatedWithdrawal')
                .withArgs();
            });
          });
        });
        context('Amount exceeds balance', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
            const bidderDepositBefore = ethers.utils.parseEther('123');
            await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
            await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
            await helpers.time.setNextBlockTimestamp((await helpers.time.latest()) + WITHDRAWAL_WAITING_PERIOD);
            await expect(
              oevAuctionHouse.connect(roles.bidder).withdraw(roles.bidder.address, bidderDepositBefore.add(1))
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'InsufficientBalance')
              .withArgs();
          });
        });
      });
      context('Amount is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
          const bidderDepositBefore = ethers.utils.parseEther('123');
          await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
          await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
          await helpers.time.setNextBlockTimestamp((await helpers.time.latest()) + WITHDRAWAL_WAITING_PERIOD);
          await expect(oevAuctionHouse.connect(roles.bidder).withdraw(roles.bidder.address, 0))
            .to.be.revertedWithCustomError(oevAuctionHouse, 'WithdrawalAmountIsZero')
            .withArgs();
        });
      });
    });
    context('Recipient address is zero', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        const bidderDepositBefore = ethers.utils.parseEther('123');
        await oevAuctionHouse.connect(roles.bidder).deposit({ value: bidderDepositBefore });
        await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
        await helpers.time.setNextBlockTimestamp((await helpers.time.latest()) + WITHDRAWAL_WAITING_PERIOD);
        await expect(oevAuctionHouse.connect(roles.bidder).withdraw(ethers.constants.AddressZero, bidderDepositBefore))
          .to.be.revertedWithCustomError(oevAuctionHouse, 'RecipientAddressIsZero')
          .withArgs();
      });
    });
  });

  describe('cancelWithdrawal', function () {
    context('Sender has an initiated withdrawal', function () {
      it('cancels the withdrawal', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        await oevAuctionHouse.connect(roles.bidder).initiateWithdrawal();
        await expect(oevAuctionHouse.connect(roles.bidder).cancelWithdrawal())
          .to.emit(oevAuctionHouse, 'CanceledWithdrawal')
          .withArgs(roles.bidder.address);
        expect(await oevAuctionHouse.bidderToEarliestWithdrawalTimestamp(roles.bidder.address)).to.equal(0);
      });
    });
    context('Sender does not have an initiated withdrawal', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deploy);
        await expect(oevAuctionHouse.connect(roles.bidder).cancelWithdrawal())
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderHasNotInitiatedWithdrawal')
          .withArgs();
      });
    });
  });

  describe('placeBidWithExpiration', function () {
    context('Chain ID is not zero', function () {
      context('Bid amount is not zero', function () {
        context('Bid details length does not exceed the maximum', function () {
          context('Bid details are not empty', function () {
            context('Bid lifetime is not larger than maximum', function () {
              context('Bid lifetime is not shorter than minimum', function () {
                context('Bid is not already placed', function () {
                  context('Collateral amount can be calculated', function () {
                    context('Maximum collateral amount is not exceeded', function () {
                      context('Maximum protocol fee amount is not exceeded', function () {
                        it('places bid with expiration', async function () {
                          const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                          const chainId = '137';
                          const proxyWithOevAddress = ethers.utils.getAddress(
                            ethers.utils.hexlify(ethers.utils.randomBytes(20))
                          );
                          const bidTopic = ethers.utils.solidityKeccak256(
                            ['uint256', 'address'],
                            [chainId, proxyWithOevAddress]
                          );
                          const bidAmount = ethers.utils.parseEther('5');
                          const updateSenderAddress = ethers.utils.getAddress(
                            ethers.utils.hexlify(ethers.utils.randomBytes(20))
                          );
                          const bidDetails = await encodeBidDetails(
                            proxyWithOevAddress,
                            BidConditionType.GTE,
                            ethers.utils.parseEther('2000'),
                            updateSenderAddress
                          );
                          const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                            chainId,
                            bidAmount
                          );
                          const expirationTimestamp = (await helpers.time.latest()) + 60 * 60;
                          const bidId = deriveBidId(roles.bidder.address, bidTopic, bidDetails);
                          const bidBefore = await oevAuctionHouse.bids(bidId);
                          expect(bidBefore.status).to.equal(BidStatus.None);
                          expect(bidBefore.expirationTimestamp).to.equal(0);
                          expect(bidBefore.collateralAmount).to.equal(0);
                          expect(bidBefore.protocolFeeAmount).to.equal(0);
                          await expect(
                            oevAuctionHouse
                              .connect(roles.bidder)
                              .placeBidWithExpiration(
                                bidTopic,
                                chainId,
                                bidAmount,
                                bidDetails,
                                collateralAmount,
                                protocolFeeAmount,
                                expirationTimestamp
                              )
                          )
                            .to.emit(oevAuctionHouse, 'PlacedBid')
                            .withArgs(
                              roles.bidder.address,
                              bidTopic,
                              bidId,
                              chainId,
                              bidAmount,
                              bidDetails,
                              expirationTimestamp,
                              collateralAmount,
                              protocolFeeAmount
                            );
                          const bid = await oevAuctionHouse.bids(bidId);
                          expect(bid.status).to.equal(BidStatus.Placed);
                          expect(bid.expirationTimestamp).to.equal(expirationTimestamp);
                          expect(bid.collateralAmount).to.equal(collateralAmount);
                          expect(bid.protocolFeeAmount).to.equal(protocolFeeAmount);
                        });
                      });
                      context('Maximum protocol fee amount is exceeded', function () {
                        it('reverts', async function () {
                          const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                          const chainId = '137';
                          const proxyWithOevAddress = ethers.utils.getAddress(
                            ethers.utils.hexlify(ethers.utils.randomBytes(20))
                          );
                          const bidTopic = ethers.utils.solidityKeccak256(
                            ['uint256', 'address'],
                            [chainId, proxyWithOevAddress]
                          );
                          const bidAmount = ethers.utils.parseEther('5');
                          const updateSenderAddress = ethers.utils.getAddress(
                            ethers.utils.hexlify(ethers.utils.randomBytes(20))
                          );
                          const bidDetails = await encodeBidDetails(
                            proxyWithOevAddress,
                            BidConditionType.GTE,
                            ethers.utils.parseEther('2000'),
                            updateSenderAddress
                          );
                          const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                            chainId,
                            bidAmount
                          );
                          const expirationTimestamp = (await helpers.time.latest()) + 60 * 60;
                          await expect(
                            oevAuctionHouse
                              .connect(roles.bidder)
                              .placeBidWithExpiration(
                                bidTopic,
                                chainId,
                                bidAmount,
                                bidDetails,
                                collateralAmount,
                                protocolFeeAmount.sub(1),
                                expirationTimestamp
                              )
                          )
                            .to.be.revertedWithCustomError(oevAuctionHouse, 'MaxProtocolFeeAmountIsExceeded')
                            .withArgs();
                        });
                      });
                    });
                    context('Maximum collateral amount is exceeded', function () {
                      it('reverts', async function () {
                        const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                        const chainId = '137';
                        const proxyWithOevAddress = ethers.utils.getAddress(
                          ethers.utils.hexlify(ethers.utils.randomBytes(20))
                        );
                        const bidTopic = ethers.utils.solidityKeccak256(
                          ['uint256', 'address'],
                          [chainId, proxyWithOevAddress]
                        );
                        const bidAmount = ethers.utils.parseEther('5');
                        const updateSenderAddress = ethers.utils.getAddress(
                          ethers.utils.hexlify(ethers.utils.randomBytes(20))
                        );
                        const bidDetails = await encodeBidDetails(
                          proxyWithOevAddress,
                          BidConditionType.GTE,
                          ethers.utils.parseEther('2000'),
                          updateSenderAddress
                        );
                        const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                          chainId,
                          bidAmount
                        );
                        const expirationTimestamp = (await helpers.time.latest()) + 60 * 60;
                        await expect(
                          oevAuctionHouse
                            .connect(roles.bidder)
                            .placeBidWithExpiration(
                              bidTopic,
                              chainId,
                              bidAmount,
                              bidDetails,
                              collateralAmount.sub(1),
                              protocolFeeAmount,
                              expirationTimestamp
                            )
                        )
                          .to.be.revertedWithCustomError(oevAuctionHouse, 'MaxCollateralAmountIsExceeded')
                          .withArgs();
                      });
                    });
                  });
                  context('Collateral amount cannot be calculated', function () {
                    it('reverts', async function () {
                      const { roles, oevAuctionHouse, collateralRateProxy } = await helpers.loadFixture(deployAndSetUp);
                      await collateralRateProxy.mock(COLLATERAL_RATE, 0);
                      const chainId = '137';
                      const proxyWithOevAddress = ethers.utils.getAddress(
                        ethers.utils.hexlify(ethers.utils.randomBytes(20))
                      );
                      const bidTopic = ethers.utils.solidityKeccak256(
                        ['uint256', 'address'],
                        [chainId, proxyWithOevAddress]
                      );
                      const bidAmount = ethers.utils.parseEther('5');
                      const updateSenderAddress = ethers.utils.getAddress(
                        ethers.utils.hexlify(ethers.utils.randomBytes(20))
                      );
                      const bidDetails = await encodeBidDetails(
                        proxyWithOevAddress,
                        BidConditionType.GTE,
                        ethers.utils.parseEther('2000'),
                        updateSenderAddress
                      );
                      const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                        chainId,
                        bidAmount
                      );
                      const nextTimestamp = (await helpers.time.latest()) + 1;
                      await helpers.time.setNextBlockTimestamp(nextTimestamp);
                      const expirationTimestamp = nextTimestamp + 60 * 60;
                      await expect(
                        oevAuctionHouse
                          .connect(roles.bidder)
                          .placeBidWithExpiration(
                            bidTopic,
                            chainId,
                            bidAmount,
                            bidDetails,
                            collateralAmount,
                            protocolFeeAmount,
                            expirationTimestamp
                          )
                      )
                        .to.be.revertedWithCustomError(oevAuctionHouse, 'CollateralRateIsStale')
                        .withArgs();
                    });
                  });
                });
                context('Bid is already placed', function () {
                  it('reverts', async function () {
                    const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                    const chainId = '137';
                    const proxyWithOevAddress = ethers.utils.getAddress(
                      ethers.utils.hexlify(ethers.utils.randomBytes(20))
                    );
                    const bidTopic = ethers.utils.solidityKeccak256(
                      ['uint256', 'address'],
                      [chainId, proxyWithOevAddress]
                    );
                    const bidAmount = ethers.utils.parseEther('5');
                    const updateSenderAddress = ethers.utils.getAddress(
                      ethers.utils.hexlify(ethers.utils.randomBytes(20))
                    );
                    const bidDetails = await encodeBidDetails(
                      proxyWithOevAddress,
                      BidConditionType.GTE,
                      ethers.utils.parseEther('2000'),
                      updateSenderAddress
                    );
                    const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                      chainId,
                      bidAmount
                    );
                    const nextTimestamp = (await helpers.time.latest()) + 1;
                    await helpers.time.setNextBlockTimestamp(nextTimestamp);
                    const expirationTimestamp = nextTimestamp + 60 * 60;
                    await oevAuctionHouse
                      .connect(roles.bidder)
                      .placeBidWithExpiration(
                        bidTopic,
                        chainId,
                        bidAmount,
                        bidDetails,
                        collateralAmount,
                        protocolFeeAmount,
                        expirationTimestamp
                      );
                    await expect(
                      oevAuctionHouse
                        .connect(roles.bidder)
                        .placeBidWithExpiration(
                          bidTopic,
                          chainId,
                          bidAmount,
                          bidDetails,
                          collateralAmount,
                          protocolFeeAmount,
                          expirationTimestamp
                        )
                    )
                      .to.be.revertedWithCustomError(oevAuctionHouse, 'BidIsAlreadyPlaced')
                      .withArgs();
                  });
                });
              });
              context('Bid lifetime is shorter than minimum', function () {
                it('reverts', async function () {
                  const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                  const chainId = '137';
                  const proxyWithOevAddress = ethers.utils.getAddress(
                    ethers.utils.hexlify(ethers.utils.randomBytes(20))
                  );
                  const bidTopic = ethers.utils.solidityKeccak256(
                    ['uint256', 'address'],
                    [chainId, proxyWithOevAddress]
                  );
                  const bidAmount = ethers.utils.parseEther('5');
                  const updateSenderAddress = ethers.utils.getAddress(
                    ethers.utils.hexlify(ethers.utils.randomBytes(20))
                  );
                  const bidDetails = await encodeBidDetails(
                    proxyWithOevAddress,
                    BidConditionType.GTE,
                    ethers.utils.parseEther('2000'),
                    updateSenderAddress
                  );
                  const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                    chainId,
                    bidAmount
                  );
                  const nextTimestamp = (await helpers.time.latest()) + 1;
                  await helpers.time.setNextBlockTimestamp(nextTimestamp);
                  const expirationTimestamp = nextTimestamp + MINIMUM_BID_LIFETIME - 1;
                  await expect(
                    oevAuctionHouse
                      .connect(roles.bidder)
                      .placeBidWithExpiration(
                        bidTopic,
                        chainId,
                        bidAmount,
                        bidDetails,
                        collateralAmount,
                        protocolFeeAmount,
                        expirationTimestamp
                      )
                  )
                    .to.be.revertedWithCustomError(oevAuctionHouse, 'BidLifetimeIsShorterThanMinimum')
                    .withArgs();
                });
              });
            });
            context('Bid lifetime is larger than maximum', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                const chainId = '137';
                const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
                const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
                const bidAmount = ethers.utils.parseEther('5');
                const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
                const bidDetails = await encodeBidDetails(
                  proxyWithOevAddress,
                  BidConditionType.GTE,
                  ethers.utils.parseEther('2000'),
                  updateSenderAddress
                );
                const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                  chainId,
                  bidAmount
                );
                const nextTimestamp = (await helpers.time.latest()) + 1;
                await helpers.time.setNextBlockTimestamp(nextTimestamp);
                const expirationTimestamp = nextTimestamp + MAXIMUM_BID_LIFETIME + 1;
                await expect(
                  oevAuctionHouse
                    .connect(roles.bidder)
                    .placeBidWithExpiration(
                      bidTopic,
                      chainId,
                      bidAmount,
                      bidDetails,
                      collateralAmount,
                      protocolFeeAmount,
                      expirationTimestamp
                    )
                )
                  .to.be.revertedWithCustomError(oevAuctionHouse, 'BidLifetimeIsLongerThanMaximum')
                  .withArgs();
              });
            });
          });
          context('Bid details are empty', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
              const chainId = '137';
              const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
              const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
              const bidAmount = ethers.utils.parseEther('5');
              const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                chainId,
                bidAmount
              );
              const nextTimestamp = (await helpers.time.latest()) + 1;
              await helpers.time.setNextBlockTimestamp(nextTimestamp);
              const expirationTimestamp = nextTimestamp + 60 * 60;
              await expect(
                oevAuctionHouse
                  .connect(roles.bidder)
                  .placeBidWithExpiration(
                    bidTopic,
                    chainId,
                    bidAmount,
                    '0x',
                    collateralAmount,
                    protocolFeeAmount,
                    expirationTimestamp
                  )
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'BidDetailsAreEmpty')
                .withArgs();
            });
          });
        });
        context('Bid details length exceeds the maximum', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
            const chainId = '137';
            const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
            const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
            const bidAmount = ethers.utils.parseEther('5');
            const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
              chainId,
              bidAmount
            );
            const nextTimestamp = (await helpers.time.latest()) + 1;
            await helpers.time.setNextBlockTimestamp(nextTimestamp);
            const expirationTimestamp = nextTimestamp + 60 * 60;
            await expect(
              oevAuctionHouse
                .connect(roles.bidder)
                .placeBidWithExpiration(
                  bidTopic,
                  chainId,
                  bidAmount,
                  `0x${'0'.repeat(MAXIMUM_BIDDER_DATA_LENGTH * 2)}00`,
                  collateralAmount,
                  protocolFeeAmount,
                  expirationTimestamp
                )
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'MaximumBidderDataLengthIsExceeded')
              .withArgs();
          });
        });
      });
      context('Bid amount is zero', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
          const chainId = '137';
          const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
          const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
          const bidAmount = ethers.BigNumber.from(0);
          const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
          const bidDetails = await encodeBidDetails(
            proxyWithOevAddress,
            BidConditionType.GTE,
            ethers.utils.parseEther('2000'),
            updateSenderAddress
          );
          const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(chainId, bidAmount);
          const nextTimestamp = (await helpers.time.latest()) + 1;
          await helpers.time.setNextBlockTimestamp(nextTimestamp);
          const expirationTimestamp = nextTimestamp + 60 * 60;
          await expect(
            oevAuctionHouse
              .connect(roles.bidder)
              .placeBidWithExpiration(
                bidTopic,
                chainId,
                bidAmount,
                bidDetails,
                collateralAmount,
                protocolFeeAmount,
                expirationTimestamp
              )
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'BidAmountIsZero')
            .withArgs();
        });
      });
    });
    context('Chain ID is zero', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
        const chainId = '0';
        const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
        const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
        const bidAmount = ethers.utils.parseEther('5');
        const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
        const bidDetails = await encodeBidDetails(
          proxyWithOevAddress,
          BidConditionType.GTE,
          ethers.utils.parseEther('2000'),
          updateSenderAddress
        );
        const nextTimestamp = (await helpers.time.latest()) + 1;
        await helpers.time.setNextBlockTimestamp(nextTimestamp);
        const expirationTimestamp = nextTimestamp + 60 * 60;
        await expect(
          oevAuctionHouse
            .connect(roles.bidder)
            .placeBidWithExpiration(
              bidTopic,
              chainId,
              bidAmount,
              bidDetails,
              ethers.constants.MaxUint256,
              ethers.constants.MaxUint256,
              expirationTimestamp
            )
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'ChainIdIsZero')
          .withArgs();
      });
    });
  });

  describe('placeBid', function () {
    it('places bid', async function () {
      const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
      const chainId = '137';
      const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
      const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
      const bidAmount = ethers.utils.parseEther('5');
      const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
      const bidDetails = await encodeBidDetails(
        proxyWithOevAddress,
        BidConditionType.GTE,
        ethers.utils.parseEther('2000'),
        updateSenderAddress
      );
      const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(chainId, bidAmount);
      const nextTimestamp = (await helpers.time.latest()) + 1;
      await helpers.time.setNextBlockTimestamp(nextTimestamp);
      const expirationTimestamp = nextTimestamp + MAXIMUM_BID_LIFETIME;
      const bidId = deriveBidId(roles.bidder.address, bidTopic, bidDetails);
      const bidBefore = await oevAuctionHouse.bids(bidId);
      expect(bidBefore.status).to.equal(BidStatus.None);
      expect(bidBefore.expirationTimestamp).to.equal(0);
      expect(bidBefore.collateralAmount).to.equal(0);
      expect(bidBefore.protocolFeeAmount).to.equal(0);
      await expect(
        oevAuctionHouse
          .connect(roles.bidder)
          .placeBid(bidTopic, chainId, bidAmount, bidDetails, collateralAmount, protocolFeeAmount)
      )
        .to.emit(oevAuctionHouse, 'PlacedBid')
        .withArgs(
          roles.bidder.address,
          bidTopic,
          bidId,
          chainId,
          bidAmount,
          bidDetails,
          expirationTimestamp,
          collateralAmount,
          protocolFeeAmount
        );
      const bid = await oevAuctionHouse.bids(bidId);
      expect(bid.status).to.equal(BidStatus.Placed);
      expect(bid.expirationTimestamp).to.equal(expirationTimestamp);
      expect(bid.collateralAmount).to.equal(collateralAmount);
      expect(bid.protocolFeeAmount).to.equal(protocolFeeAmount);
    });
  });

  describe('expediteBidExpiration', function () {
    context('Bid is awaiting award', function () {
      context('Bid has not expired', function () {
        context('Timestamp expedites bid expiration', function () {
          context('Resulting bid lifetime is not shorter than minimum', function () {
            it('expedites bid expiration', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
              const chainId = '137';
              const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
              const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
              const bidAmount = ethers.utils.parseEther('5');
              const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
              const bidDetails = await encodeBidDetails(
                proxyWithOevAddress,
                BidConditionType.GTE,
                ethers.utils.parseEther('2000'),
                updateSenderAddress
              );
              const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                chainId,
                bidAmount
              );
              const nextTimestamp = (await helpers.time.latest()) + 1;
              await helpers.time.setNextBlockTimestamp(nextTimestamp);
              const expirationTimestamp = nextTimestamp + 60 * 60;
              const bidId = deriveBidId(roles.bidder.address, bidTopic, bidDetails);
              await oevAuctionHouse
                .connect(roles.bidder)
                .placeBidWithExpiration(
                  bidTopic,
                  chainId,
                  bidAmount,
                  bidDetails,
                  collateralAmount,
                  protocolFeeAmount,
                  expirationTimestamp
                );
              const expeditedExpirationTimestamp = expirationTimestamp - 30 * 60;
              await expect(
                oevAuctionHouse
                  .connect(roles.bidder)
                  .expediteBidExpiration(bidTopic, ethers.utils.keccak256(bidDetails), expeditedExpirationTimestamp)
              )
                .to.emit(oevAuctionHouse, 'ExpeditedBidExpiration')
                .withArgs(roles.bidder.address, bidTopic, bidId, expeditedExpirationTimestamp);
              const bid = await oevAuctionHouse.bids(bidId);
              expect(bid.status).to.equal(BidStatus.Placed);
              expect(bid.expirationTimestamp).to.equal(expeditedExpirationTimestamp);
              expect(bid.collateralAmount).to.equal(collateralAmount);
              expect(bid.protocolFeeAmount).to.equal(protocolFeeAmount);
            });
          });
          context('Resulting bid lifetime is shorter than minimum', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
              const chainId = '137';
              const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
              const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
              const bidAmount = ethers.utils.parseEther('5');
              const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
              const bidDetails = await encodeBidDetails(
                proxyWithOevAddress,
                BidConditionType.GTE,
                ethers.utils.parseEther('2000'),
                updateSenderAddress
              );
              const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                chainId,
                bidAmount
              );
              const nextTimestamp = (await helpers.time.latest()) + 1;
              await helpers.time.setNextBlockTimestamp(nextTimestamp);
              const expirationTimestamp = nextTimestamp + 60 * 60;
              await oevAuctionHouse
                .connect(roles.bidder)
                .placeBidWithExpiration(
                  bidTopic,
                  chainId,
                  bidAmount,
                  bidDetails,
                  collateralAmount,
                  protocolFeeAmount,
                  expirationTimestamp
                );
              const nextTimestamp2 = (await helpers.time.latest()) + 1;
              await helpers.time.setNextBlockTimestamp(nextTimestamp2);
              const expeditedExpirationTimestamp = nextTimestamp2 + MINIMUM_BID_LIFETIME - 1;
              await expect(
                oevAuctionHouse
                  .connect(roles.bidder)
                  .expediteBidExpiration(bidTopic, ethers.utils.keccak256(bidDetails), expeditedExpirationTimestamp)
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'BidLifetimeIsShorterThanMinimum')
                .withArgs();
            });
          });
        });
        context('Timestamp does not expedite bid expiration', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
            const chainId = '137';
            const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
            const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
            const bidAmount = ethers.utils.parseEther('5');
            const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
            const bidDetails = await encodeBidDetails(
              proxyWithOevAddress,
              BidConditionType.GTE,
              ethers.utils.parseEther('2000'),
              updateSenderAddress
            );
            const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
              chainId,
              bidAmount
            );
            const nextTimestamp = (await helpers.time.latest()) + 1;
            await helpers.time.setNextBlockTimestamp(nextTimestamp);
            const expirationTimestamp = nextTimestamp + 60 * 60;
            await oevAuctionHouse
              .connect(roles.bidder)
              .placeBidWithExpiration(
                bidTopic,
                chainId,
                bidAmount,
                bidDetails,
                collateralAmount,
                protocolFeeAmount,
                expirationTimestamp
              );
            await expect(
              oevAuctionHouse
                .connect(roles.bidder)
                .expediteBidExpiration(bidTopic, ethers.utils.keccak256(bidDetails), expirationTimestamp)
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'TimestampDoesNotExpediteExpiration')
              .withArgs();
          });
        });
      });
      context('Bid has expired', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
          const chainId = '137';
          const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
          const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
          const bidAmount = ethers.utils.parseEther('5');
          const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
          const bidDetails = await encodeBidDetails(
            proxyWithOevAddress,
            BidConditionType.GTE,
            ethers.utils.parseEther('2000'),
            updateSenderAddress
          );
          const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(chainId, bidAmount);
          const nextTimestamp = (await helpers.time.latest()) + 1;
          await helpers.time.setNextBlockTimestamp(nextTimestamp);
          const expirationTimestamp = nextTimestamp + 60 * 60;
          await oevAuctionHouse
            .connect(roles.bidder)
            .placeBidWithExpiration(
              bidTopic,
              chainId,
              bidAmount,
              bidDetails,
              collateralAmount,
              protocolFeeAmount,
              expirationTimestamp
            );
          await helpers.time.setNextBlockTimestamp(expirationTimestamp);
          const expeditedExpirationTimestamp = expirationTimestamp - 30 * 60;
          await expect(
            oevAuctionHouse
              .connect(roles.bidder)
              .expediteBidExpiration(bidTopic, ethers.utils.keccak256(bidDetails), expeditedExpirationTimestamp)
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'BidHasExpired')
            .withArgs();
        });
      });
    });
    context('Bid is not awaiting award', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
        const chainId = '137';
        const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
        const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
        const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
        const bidDetails = await encodeBidDetails(
          proxyWithOevAddress,
          BidConditionType.GTE,
          ethers.utils.parseEther('2000'),
          updateSenderAddress
        );
        const nextTimestamp = (await helpers.time.latest()) + 1;
        await helpers.time.setNextBlockTimestamp(nextTimestamp);
        const expirationTimestamp = nextTimestamp + 60 * 60;
        const expeditedExpirationTimestamp = expirationTimestamp - 30 * 60;
        await expect(
          oevAuctionHouse
            .connect(roles.bidder)
            .expediteBidExpiration(bidTopic, ethers.utils.keccak256(bidDetails), expeditedExpirationTimestamp)
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'BidIsNotAwaitingAward')
          .withArgs();
      });
    });
  });

  describe('expediteBidExpirationMaximally', function () {
    it('expedites bid expiration maximally', async function () {
      const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
      const chainId = '137';
      const proxyWithOevAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
      const bidTopic = ethers.utils.solidityKeccak256(['uint256', 'address'], [chainId, proxyWithOevAddress]);
      const bidAmount = ethers.utils.parseEther('5');
      const updateSenderAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
      const bidDetails = await encodeBidDetails(
        proxyWithOevAddress,
        BidConditionType.GTE,
        ethers.utils.parseEther('2000'),
        updateSenderAddress
      );
      const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(chainId, bidAmount);
      const nextTimestamp = (await helpers.time.latest()) + 1;
      await helpers.time.setNextBlockTimestamp(nextTimestamp);
      const expirationTimestamp = nextTimestamp + 60 * 60;
      const bidId = deriveBidId(roles.bidder.address, bidTopic, bidDetails);
      await oevAuctionHouse
        .connect(roles.bidder)
        .placeBidWithExpiration(
          bidTopic,
          chainId,
          bidAmount,
          bidDetails,
          collateralAmount,
          protocolFeeAmount,
          expirationTimestamp
        );
      const nextTimestamp2 = (await helpers.time.latest()) + 1;
      await helpers.time.setNextBlockTimestamp(nextTimestamp2);
      const expeditedExpirationTimestamp = nextTimestamp2 + MINIMUM_BID_LIFETIME;
      await expect(
        oevAuctionHouse
          .connect(roles.bidder)
          .expediteBidExpirationMaximally(bidTopic, ethers.utils.keccak256(bidDetails))
      )
        .to.emit(oevAuctionHouse, 'ExpeditedBidExpiration')
        .withArgs(roles.bidder.address, bidTopic, bidId, expeditedExpirationTimestamp);
      const bid = await oevAuctionHouse.bids(bidId);
      expect(bid.status).to.equal(BidStatus.Placed);
      expect(bid.expirationTimestamp).to.equal(expeditedExpirationTimestamp);
      expect(bid.collateralAmount).to.equal(collateralAmount);
      expect(bid.protocolFeeAmount).to.equal(protocolFeeAmount);
    });
  });

  describe('awardBid', function () {
    context('Sender is an auctioneer', function () {
      context('Award details length does not exceed the maximum', function () {
        context('Award details are not empty', function () {
          context('Award has not expired', function () {
            context('Bid is awaiting award', function () {
              context('Bid has not expired', function () {
                context(
                  'Bidder balance is not lower than the larger of collateral and protocol fee amounts',
                  function () {
                    context('Collateral amount is larger than protocol fee amount', function () {
                      it('awards the bid', async function () {
                        const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
                          deployAndSetUpAndPlaceBid
                        );
                        const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
                        await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
                        const awardDetails = ethers.utils.solidityPack(
                          ['string'],
                          ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
                        );
                        const nextTimestamp = (await helpers.time.latest()) + 1;
                        await helpers.time.setNextBlockTimestamp(nextTimestamp);
                        const expectedUpdatedExpirationTimestamp = nextTimestamp + FULFILLMENT_REPORTING_PERIOD;
                        const expectedBidderDepositAfterBidAward = totalBidderDeposit.sub(
                          bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                            ? bidParameters.collateralAmount
                            : bidParameters.protocolFeeAmount
                        );
                        await expect(
                          oevAuctionHouse
                            .connect(roles.auctioneer)
                            .awardBid(
                              bidParameters.bidderAddress,
                              bidParameters.bidTopic,
                              ethers.utils.keccak256(bidParameters.bidDetails),
                              awardDetails,
                              nextTimestamp + 60
                            )
                        )
                          .to.emit(oevAuctionHouse, 'AwardedBid')
                          .withArgs(
                            bidParameters.bidderAddress,
                            bidParameters.bidTopic,
                            bidParameters.bidId,
                            awardDetails,
                            expectedBidderDepositAfterBidAward
                          );
                        const bid = await oevAuctionHouse.bids(bidParameters.bidId);
                        expect(bid.status).to.equal(BidStatus.Awarded);
                        expect(bid.expirationTimestamp).to.equal(expectedUpdatedExpirationTimestamp);
                        expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
                        expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
                        expect(await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)).to.equal(
                          expectedBidderDepositAfterBidAward
                        );
                      });
                    });
                    context('Collateral amount is not larger than protocol fee amount', function () {
                      it('awards the bid', async function () {
                        const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
                          deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmount
                        );
                        const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
                        await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
                        const awardDetails = ethers.utils.solidityPack(
                          ['string'],
                          ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
                        );
                        const nextTimestamp = (await helpers.time.latest()) + 1;
                        await helpers.time.setNextBlockTimestamp(nextTimestamp);
                        const expectedUpdatedExpirationTimestamp = nextTimestamp + FULFILLMENT_REPORTING_PERIOD;
                        const expectedBidderDepositAfterBidAward = totalBidderDeposit.sub(
                          bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                            ? bidParameters.collateralAmount
                            : bidParameters.protocolFeeAmount
                        );
                        await expect(
                          oevAuctionHouse
                            .connect(roles.auctioneer)
                            .awardBid(
                              bidParameters.bidderAddress,
                              bidParameters.bidTopic,
                              ethers.utils.keccak256(bidParameters.bidDetails),
                              awardDetails,
                              nextTimestamp + 60
                            )
                        )
                          .to.emit(oevAuctionHouse, 'AwardedBid')
                          .withArgs(
                            bidParameters.bidderAddress,
                            bidParameters.bidTopic,
                            bidParameters.bidId,
                            awardDetails,
                            expectedBidderDepositAfterBidAward
                          );
                        const bid = await oevAuctionHouse.bids(bidParameters.bidId);
                        expect(bid.status).to.equal(BidStatus.Awarded);
                        expect(bid.expirationTimestamp).to.equal(expectedUpdatedExpirationTimestamp);
                        expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
                        expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
                        expect(await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)).to.equal(
                          expectedBidderDepositAfterBidAward
                        );
                      });
                    });
                  }
                );
                context('Bidder balance is lower than the larger of collateral and protocol fee amounts', function () {
                  it('reverts', async function () {
                    const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
                      deployAndSetUpAndPlaceBid
                    );
                    const totalBidderDeposit = (
                      bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                        ? bidParameters.collateralAmount
                        : bidParameters.protocolFeeAmount
                    ).sub(1);
                    await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
                    const awardDetails = ethers.utils.solidityPack(
                      ['string'],
                      ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
                    );
                    await expect(
                      oevAuctionHouse
                        .connect(roles.auctioneer)
                        .awardBid(
                          bidParameters.bidderAddress,
                          bidParameters.bidTopic,
                          ethers.utils.keccak256(bidParameters.bidDetails),
                          awardDetails,
                          (await helpers.time.latest()) + 60
                        )
                    )
                      .to.be.revertedWithCustomError(oevAuctionHouse, 'BidderBalanceIsLowerThanTheLockedAmount')
                      .withArgs();
                  });
                });
              });
              context('Bid has expired', function () {
                it('reverts', async function () {
                  const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
                    deployAndSetUpAndPlaceBid
                  );
                  const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
                  await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
                  const awardDetails = ethers.utils.solidityPack(
                    ['string'],
                    ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
                  );
                  await helpers.time.setNextBlockTimestamp(bidParameters.expirationTimestamp);
                  await expect(
                    oevAuctionHouse
                      .connect(roles.auctioneer)
                      .awardBid(
                        bidParameters.bidderAddress,
                        bidParameters.bidTopic,
                        ethers.utils.keccak256(bidParameters.bidDetails),
                        awardDetails,
                        bidParameters.expirationTimestamp + 60
                      )
                  )
                    .to.be.revertedWithCustomError(oevAuctionHouse, 'BidHasExpired')
                    .withArgs();
                });
              });
            });
            context('Bid is not awaiting award', function () {
              it('reverts', async function () {
                const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(deployAndSetUpAndPlaceBid);
                const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
                await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
                const awardDetails = ethers.utils.solidityPack(
                  ['string'],
                  ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
                );
                await oevAuctionHouse
                  .connect(roles.auctioneer)
                  .awardBid(
                    bidParameters.bidderAddress,
                    bidParameters.bidTopic,
                    ethers.utils.keccak256(bidParameters.bidDetails),
                    awardDetails,
                    (await helpers.time.latest()) + 60
                  );
                await expect(
                  oevAuctionHouse
                    .connect(roles.auctioneer)
                    .awardBid(
                      bidParameters.bidderAddress,
                      bidParameters.bidTopic,
                      ethers.utils.keccak256(bidParameters.bidDetails),
                      awardDetails,
                      (await helpers.time.latest()) + 60
                    )
                )
                  .to.be.revertedWithCustomError(oevAuctionHouse, 'BidIsNotAwaitingAward')
                  .withArgs();
              });
            });
          });
          context('Award has expired', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(deployAndSetUpAndPlaceBid);
              const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
              await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
              const awardDetails = ethers.utils.solidityPack(
                ['string'],
                ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
              );
              const nextTimestamp = (await helpers.time.latest()) + 1;
              await helpers.time.setNextBlockTimestamp(nextTimestamp);
              await expect(
                oevAuctionHouse
                  .connect(roles.auctioneer)
                  .awardBid(
                    bidParameters.bidderAddress,
                    bidParameters.bidTopic,
                    ethers.utils.keccak256(bidParameters.bidDetails),
                    awardDetails,
                    nextTimestamp
                  )
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'AwardHasExpired')
                .withArgs();
            });
          });
        });
        context('Award details are empty', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(deployAndSetUpAndPlaceBid);
            const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
            await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
            await expect(
              oevAuctionHouse
                .connect(roles.auctioneer)
                .awardBid(
                  bidParameters.bidderAddress,
                  bidParameters.bidTopic,
                  ethers.utils.keccak256(bidParameters.bidDetails),
                  '0x',
                  (await helpers.time.latest()) + 60
                )
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'AwardDetailsAreEmpty')
              .withArgs();
          });
        });
      });
      context('Award details length exceeds the maximum', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(deployAndSetUpAndPlaceBid);
          const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
          await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
          await expect(
            oevAuctionHouse
              .connect(roles.auctioneer)
              .awardBid(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails),
                `0x${'0'.repeat(MAXIMUM_AUCTIONEER_DATA_LENGTH * 2)}00`,
                (await helpers.time.latest()) + 60
              )
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'MaximumAuctioneerDataLengthIsExceeded')
            .withArgs();
        });
      });
    });
    context('Sender is not an auctioneer', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(deployAndSetUpAndPlaceBid);
        const totalBidderDeposit = bidParameters.collateralAmount.mul(4);
        await oevAuctionHouse.connect(roles.bidder).deposit({ value: totalBidderDeposit });
        const awardDetails = ethers.utils.solidityPack(
          ['string'],
          ['Calldata that calls updateOevProxyDataFeedWithSignedData() of Api3ServerV1']
        );
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .awardBid(
              bidParameters.bidderAddress,
              bidParameters.bidTopic,
              ethers.utils.keccak256(bidParameters.bidDetails),
              awardDetails,
              (await helpers.time.latest()) + 60
            )
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAnAuctioneer')
          .withArgs();
      });
    });
  });

  describe('reportFulfillment', function () {
    context('Fulfillment details length does not exceed the maximum', function () {
      context('Fulfillment details are not empty', function () {
        context('Bid is awaiting fulfillment report', function () {
          context('Bid has not expired', function () {
            it('reports fulfillment', async function () {
              const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
                deployAndSetUpAndPlaceBidAndAwardBid
              );
              const fulfillmentDetails = ethers.utils.defaultAbiCoder.encode(
                ['string'],
                ['Hash of the OEV update transaction']
              );
              const expirationTimestampBeforeFulfillmentReport = (await oevAuctionHouse.bids(bidParameters.bidId))
                .expirationTimestamp;
              await expect(
                oevAuctionHouse
                  .connect(roles.bidder)
                  .reportFulfillment(
                    bidParameters.bidTopic,
                    ethers.utils.keccak256(bidParameters.bidDetails),
                    fulfillmentDetails
                  )
              )
                .to.emit(oevAuctionHouse, 'ReportedFulfillment')
                .withArgs(roles.bidder.address, bidParameters.bidTopic, bidParameters.bidId, fulfillmentDetails);
              const bid = await oevAuctionHouse.bids(bidParameters.bidId);
              expect(bid.status).to.equal(BidStatus.FulfillmentReported);
              expect(bid.expirationTimestamp).to.equal(expirationTimestampBeforeFulfillmentReport);
              expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
              expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
            });
          });
          describe('Bid has expired', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
                deployAndSetUpAndPlaceBidAndAwardBid
              );
              const fulfillmentDetails = ethers.utils.defaultAbiCoder.encode(
                ['string'],
                ['Hash of the OEV update transaction']
              );
              await helpers.time.setNextBlockTimestamp(
                (
                  await oevAuctionHouse.bids(bidParameters.bidId)
                ).expirationTimestamp
              );
              await expect(
                oevAuctionHouse
                  .connect(roles.bidder)
                  .reportFulfillment(
                    bidParameters.bidTopic,
                    ethers.utils.keccak256(bidParameters.bidDetails),
                    fulfillmentDetails
                  )
              )
                .to.be.revertedWithCustomError(oevAuctionHouse, 'BidHasExpired')
                .withArgs();
            });
          });
        });
        describe('Bid is not awaiting fulfillment report', function () {
          it('reverts', async function () {
            const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBid
            );
            const fulfillmentDetails = ethers.utils.defaultAbiCoder.encode(
              ['string'],
              ['Hash of the OEV update transaction']
            );
            await oevAuctionHouse
              .connect(roles.bidder)
              .reportFulfillment(
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails),
                fulfillmentDetails
              );
            await expect(
              oevAuctionHouse
                .connect(roles.bidder)
                .reportFulfillment(
                  bidParameters.bidTopic,
                  ethers.utils.keccak256(bidParameters.bidDetails),
                  fulfillmentDetails
                )
            )
              .to.be.revertedWithCustomError(oevAuctionHouse, 'BidIsNotAwaitingFulfillmentReport')
              .withArgs();
          });
        });
      });
      describe('Fulfillment details are not empty', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBid
          );
          await expect(
            oevAuctionHouse
              .connect(roles.bidder)
              .reportFulfillment(bidParameters.bidTopic, ethers.utils.keccak256(bidParameters.bidDetails), '0x')
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'FulfillmentDetailsAreEmpty')
            .withArgs();
        });
      });
    });
    context('Fulfillment details length exceeds the maximum', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
          deployAndSetUpAndPlaceBidAndAwardBid
        );
        await expect(
          oevAuctionHouse
            .connect(roles.bidder)
            .reportFulfillment(
              bidParameters.bidTopic,
              ethers.utils.keccak256(bidParameters.bidDetails),
              `0x${'0'.repeat(MAXIMUM_BIDDER_DATA_LENGTH * 2)}00`
            )
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'MaximumBidderDataLengthIsExceeded')
          .withArgs();
      });
    });
  });

  describe('confirmFulfillment', function () {
    context('Sender is an auctioneer', function () {
      context('Bid is awaiting fulfillment confirmation', function () {
        context('Collateral amount is larger than protocol fee amount', function () {
          it('confirms fulfillment', async function () {
            const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment
            );
            const expirationTimestampBeforeFulfillmentConfirmation = (await oevAuctionHouse.bids(bidParameters.bidId))
              .expirationTimestamp;
            const expectedBidderDepositAfterFulfillmentConfirmation = (
              await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)
            )
              .add(
                bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                  ? bidParameters.collateralAmount
                  : bidParameters.protocolFeeAmount
              )
              .sub(bidParameters.protocolFeeAmount);
            const expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation = (
              await oevAuctionHouse.accumulatedProtocolFees()
            ).add(bidParameters.protocolFeeAmount);
            const fulfillmentConfirmationResponse = await oevAuctionHouse
              .connect(roles.auctioneer)
              .callStatic.confirmFulfillment(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails)
              );
            expect(fulfillmentConfirmationResponse.bidderBalance).to.equal(
              expectedBidderDepositAfterFulfillmentConfirmation
            );
            expect(fulfillmentConfirmationResponse.accumulatedProtocolFees_).to.equal(
              expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation
            );
            await expect(
              oevAuctionHouse
                .connect(roles.auctioneer)
                .confirmFulfillment(
                  bidParameters.bidderAddress,
                  bidParameters.bidTopic,
                  ethers.utils.keccak256(bidParameters.bidDetails)
                )
            )
              .to.emit(oevAuctionHouse, 'ConfirmedFulfillment')
              .withArgs(
                roles.bidder.address,
                bidParameters.bidTopic,
                bidParameters.bidId,
                expectedBidderDepositAfterFulfillmentConfirmation,
                expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation
              );
            const bid = await oevAuctionHouse.bids(bidParameters.bidId);
            expect(bid.status).to.equal(BidStatus.FulfillmentConfirmed);
            expect(bid.expirationTimestamp).to.equal(expirationTimestampBeforeFulfillmentConfirmation);
            expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
            expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
            expect(await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)).to.equal(
              expectedBidderDepositAfterFulfillmentConfirmation
            );
            expect(await oevAuctionHouse.accumulatedProtocolFees()).to.equal(
              expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation
            );
          });
        });
        context('Collateral amount is not larger than protocol fee amount', function () {
          it('confirms fulfillment', async function () {
            const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmountAndAwardBidAndReportFulfillment
            );
            const expirationTimestampBeforeFulfillmentConfirmation = (await oevAuctionHouse.bids(bidParameters.bidId))
              .expirationTimestamp;
            const expectedBidderDepositAfterFulfillmentConfirmation = (
              await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)
            )
              .add(
                bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                  ? bidParameters.collateralAmount
                  : bidParameters.protocolFeeAmount
              )
              .sub(bidParameters.protocolFeeAmount);
            const expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation = (
              await oevAuctionHouse.accumulatedProtocolFees()
            ).add(bidParameters.protocolFeeAmount);
            const fulfillmentConfirmationResponse = await oevAuctionHouse
              .connect(roles.auctioneer)
              .callStatic.confirmFulfillment(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails)
              );
            expect(fulfillmentConfirmationResponse.bidderBalance).to.equal(
              expectedBidderDepositAfterFulfillmentConfirmation
            );
            expect(fulfillmentConfirmationResponse.accumulatedProtocolFees_).to.equal(
              expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation
            );
            await expect(
              oevAuctionHouse
                .connect(roles.auctioneer)
                .confirmFulfillment(
                  bidParameters.bidderAddress,
                  bidParameters.bidTopic,
                  ethers.utils.keccak256(bidParameters.bidDetails)
                )
            )
              .to.emit(oevAuctionHouse, 'ConfirmedFulfillment')
              .withArgs(
                roles.bidder.address,
                bidParameters.bidTopic,
                bidParameters.bidId,
                expectedBidderDepositAfterFulfillmentConfirmation,
                expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation
              );
            const bid = await oevAuctionHouse.bids(bidParameters.bidId);
            expect(bid.status).to.equal(BidStatus.FulfillmentConfirmed);
            expect(bid.expirationTimestamp).to.equal(expirationTimestampBeforeFulfillmentConfirmation);
            expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
            expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
            expect(await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)).to.equal(
              expectedBidderDepositAfterFulfillmentConfirmation
            );
            expect(await oevAuctionHouse.accumulatedProtocolFees()).to.equal(
              expectedAccumulatedProtocolFeesAfterFulfillmentConfirmation
            );
          });
        });
      });
      describe('Bid is not awaiting fulfillment confirmation', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment
          );
          await oevAuctionHouse
            .connect(roles.auctioneer)
            .confirmFulfillment(
              bidParameters.bidderAddress,
              bidParameters.bidTopic,
              ethers.utils.keccak256(bidParameters.bidDetails)
            );
          await expect(
            oevAuctionHouse
              .connect(roles.auctioneer)
              .confirmFulfillment(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails)
              )
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'BidFulfillmentCannotBeConfirmed')
            .withArgs();
        });
      });
    });
    describe('Sender is not an auctioneer', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
          deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment
        );
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .confirmFulfillment(
              bidParameters.bidderAddress,
              bidParameters.bidTopic,
              ethers.utils.keccak256(bidParameters.bidDetails)
            )
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAnAuctioneer')
          .withArgs();
      });
    });
  });

  describe('contradictFulfillment', function () {
    context('Sender is an auctioneer', function () {
      context('Bid is awaiting fulfillment confirmation', function () {
        context('Collateral amount is larger than protocol fee amount', function () {
          it('contradicts fulfillment', async function () {
            const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment
            );
            const expirationTimestampBeforeFulfillmentContradiction = (await oevAuctionHouse.bids(bidParameters.bidId))
              .expirationTimestamp;
            const expectedBidderDepositAfterFulfillmentContradiction = (
              await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)
            )
              .add(
                bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                  ? bidParameters.collateralAmount
                  : bidParameters.protocolFeeAmount
              )
              .sub(bidParameters.collateralAmount);
            const expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction = (
              await oevAuctionHouse.accumulatedSlashedCollateral()
            ).add(bidParameters.collateralAmount);
            const fulfillmentContradictionResponse = await oevAuctionHouse
              .connect(roles.auctioneer)
              .callStatic.contradictFulfillment(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails)
              );
            expect(fulfillmentContradictionResponse.bidderBalance).to.equal(
              expectedBidderDepositAfterFulfillmentContradiction
            );
            expect(fulfillmentContradictionResponse.accumulatedSlashedCollateral_).to.equal(
              expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction
            );
            await expect(
              oevAuctionHouse
                .connect(roles.auctioneer)
                .contradictFulfillment(
                  bidParameters.bidderAddress,
                  bidParameters.bidTopic,
                  ethers.utils.keccak256(bidParameters.bidDetails)
                )
            )
              .to.emit(oevAuctionHouse, 'ContradictedFulfillment')
              .withArgs(
                roles.bidder.address,
                bidParameters.bidTopic,
                bidParameters.bidId,
                expectedBidderDepositAfterFulfillmentContradiction,
                expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction
              );
            const bid = await oevAuctionHouse.bids(bidParameters.bidId);
            expect(bid.status).to.equal(BidStatus.FulfillmentContradicted);
            expect(bid.expirationTimestamp).to.equal(expirationTimestampBeforeFulfillmentContradiction);
            expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
            expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
            expect(await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)).to.equal(
              expectedBidderDepositAfterFulfillmentContradiction
            );
            expect(await oevAuctionHouse.accumulatedSlashedCollateral()).to.equal(
              expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction
            );
          });
        });
        context('Collateral amount is not larger than protocol fee amount', function () {
          it('contradicts fulfillment', async function () {
            const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
              deployAndSetUpAndPlaceBidWithLargerProtocolFeeAmountAndAwardBidAndReportFulfillment
            );
            const expirationTimestampBeforeFulfillmentContradiction = (await oevAuctionHouse.bids(bidParameters.bidId))
              .expirationTimestamp;
            const expectedBidderDepositAfterFulfillmentContradiction = (
              await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)
            )
              .add(
                bidParameters.collateralAmount.gt(bidParameters.protocolFeeAmount)
                  ? bidParameters.collateralAmount
                  : bidParameters.protocolFeeAmount
              )
              .sub(bidParameters.collateralAmount);
            const expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction = (
              await oevAuctionHouse.accumulatedSlashedCollateral()
            ).add(bidParameters.collateralAmount);
            const fulfillmentContradictionResponse = await oevAuctionHouse
              .connect(roles.auctioneer)
              .callStatic.contradictFulfillment(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails)
              );
            expect(fulfillmentContradictionResponse.bidderBalance).to.equal(
              expectedBidderDepositAfterFulfillmentContradiction
            );
            expect(fulfillmentContradictionResponse.accumulatedSlashedCollateral_).to.equal(
              expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction
            );
            await expect(
              oevAuctionHouse
                .connect(roles.auctioneer)
                .contradictFulfillment(
                  bidParameters.bidderAddress,
                  bidParameters.bidTopic,
                  ethers.utils.keccak256(bidParameters.bidDetails)
                )
            )
              .to.emit(oevAuctionHouse, 'ContradictedFulfillment')
              .withArgs(
                roles.bidder.address,
                bidParameters.bidTopic,
                bidParameters.bidId,
                expectedBidderDepositAfterFulfillmentContradiction,
                expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction
              );
            const bid = await oevAuctionHouse.bids(bidParameters.bidId);
            expect(bid.status).to.equal(BidStatus.FulfillmentContradicted);
            expect(bid.expirationTimestamp).to.equal(expirationTimestampBeforeFulfillmentContradiction);
            expect(bid.collateralAmount).to.equal(bidParameters.collateralAmount);
            expect(bid.protocolFeeAmount).to.equal(bidParameters.protocolFeeAmount);
            expect(await oevAuctionHouse.bidderToBalance(bidParameters.bidderAddress)).to.equal(
              expectedBidderDepositAfterFulfillmentContradiction
            );
            expect(await oevAuctionHouse.accumulatedSlashedCollateral()).to.equal(
              expectedAccumulatedSlashedCollateralAfterFulfillmentContradiction
            );
          });
        });
      });
      describe('Bid is not awaiting fulfillment confirmation', function () {
        it('reverts', async function () {
          const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
            deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment
          );
          await oevAuctionHouse
            .connect(roles.auctioneer)
            .contradictFulfillment(
              bidParameters.bidderAddress,
              bidParameters.bidTopic,
              ethers.utils.keccak256(bidParameters.bidDetails)
            );
          await expect(
            oevAuctionHouse
              .connect(roles.auctioneer)
              .contradictFulfillment(
                bidParameters.bidderAddress,
                bidParameters.bidTopic,
                ethers.utils.keccak256(bidParameters.bidDetails)
              )
          )
            .to.be.revertedWithCustomError(oevAuctionHouse, 'BidFulfillmentCannotBeContradicted')
            .withArgs();
        });
      });
    });
    describe('Sender is not an auctioneer', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse, bidParameters } = await helpers.loadFixture(
          deployAndSetUpAndPlaceBidAndAwardBidAndReportFulfillment
        );
        await expect(
          oevAuctionHouse
            .connect(roles.randomPerson)
            .contradictFulfillment(
              bidParameters.bidderAddress,
              bidParameters.bidTopic,
              ethers.utils.keccak256(bidParameters.bidDetails)
            )
        )
          .to.be.revertedWithCustomError(oevAuctionHouse, 'SenderIsNotAnAuctioneer')
          .withArgs();
      });
    });
  });

  describe('getCurrentCollateralAndProtocolFeeAmounts', function () {
    context('Collateral rate proxy is valid', function () {
      context('Collateral rate is positive', function () {
        context('Collateral rate is not stale', function () {
          context('Native currency rate proxy is valid', function () {
            context('Native currency rate is positive', function () {
              context('Native currency rate is not stale', function () {
                context(
                  'Collateral and protocol fee amounts are small enough to be typecasted to uint104',
                  function () {
                    it('gets current collateral and protocol fee amounts', async function () {
                      const { oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                      const chainId = '137';
                      const bidAmount = ethers.utils.parseEther('5');
                      const { collateralAmount, protocolFeeAmount } = calculateCollateralAndProtocolFeeAmounts(
                        chainId,
                        bidAmount
                      );
                      const currentCollateralAndProtocolFeeAmounts =
                        await oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount);
                      expect(currentCollateralAndProtocolFeeAmounts.collateralAmount).to.equal(collateralAmount);
                      expect(currentCollateralAndProtocolFeeAmounts.protocolFeeAmount).to.equal(protocolFeeAmount);
                    });
                  }
                );
                context(
                  'Collateral and protocol fee amounts are not small enough to be typecasted to uint104',
                  function () {
                    it('revert', async function () {
                      const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
                      const chainId = '137';
                      const { collateralAmount } = await calculateCollateralAndProtocolFeeAmounts(
                        chainId,
                        ethers.utils.parseEther('1')
                      );
                      const bidAmountCausingCollateralAmountOverflow = ethers.BigNumber.from(2)
                        .pow(104)
                        .mul(ethers.utils.parseEther('1'))
                        .div(collateralAmount);
                      await expect(
                        oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(
                          chainId,
                          bidAmountCausingCollateralAmountOverflow
                        )
                      ).to.be.revertedWith('Value does not fit in uint104');
                      await oevAuctionHouse
                        .connect(roles.manager)
                        .setProtocolFeeInBasisPoints(COLLATERAL_AMOUNT_IN_BASIS_POINTS + 2.5 * 100);
                      const { protocolFeeAmount } = await calculateCollateralAndProtocolFeeAmounts(
                        chainId,
                        ethers.utils.parseEther('1')
                      );
                      const bidAmountCausingProtocolFeeAmountOverflow = ethers.BigNumber.from(2)
                        .pow(104)
                        .mul(ethers.utils.parseEther('1'))
                        .div(protocolFeeAmount);
                      await expect(
                        oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(
                          chainId,
                          bidAmountCausingProtocolFeeAmountOverflow
                        )
                      ).to.be.revertedWith('Value does not fit in uint104');
                    });
                  }
                );
              });
              context('Native currency rate is stale', function () {
                it('reverts', async function () {
                  const { oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(
                    deployAndSetUp
                  );
                  const chainId = '137';
                  const bidAmount = ethers.utils.parseEther('5');
                  const nextTimestamp = (await helpers.time.latest()) + 1;
                  await helpers.time.setNextBlockTimestamp(nextTimestamp);
                  await chainIdToNativeCurrencyRateProxy[chainId].mock(
                    CHAIN_ID_TO_PRICE[chainId],
                    nextTimestamp - MAXIMUM_RATE_AGE
                  );
                  await expect(oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount))
                    .to.be.revertedWithCustomError(oevAuctionHouse, 'NativeCurrencyRateIsStale')
                    .withArgs();
                });
              });
            });
            context('Native currency rate is not positive', function () {
              it('reverts', async function () {
                const { oevAuctionHouse, chainIdToNativeCurrencyRateProxy } = await helpers.loadFixture(deployAndSetUp);
                const chainId = '137';
                const bidAmount = ethers.utils.parseEther('5');
                await chainIdToNativeCurrencyRateProxy[chainId].mock(0, Math.floor(Date.now() / 1000));
                await expect(oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount))
                  .to.be.revertedWithCustomError(oevAuctionHouse, 'NativeCurrencyRateIsNotPositive')
                  .withArgs();
              });
            });
          });
          context('Native currency rate proxy is not valid', function () {
            it('reverts', async function () {
              const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
              const chainId = '137';
              const bidAmount = ethers.utils.parseEther('5');
              await oevAuctionHouse
                .connect(roles.manager)
                .setChainNativeCurrencyRateProxy(chainId, oevAuctionHouse.address);
              await expect(
                oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount)
              ).to.be.revertedWithoutReason;
            });
          });
        });
        context('Collateral rate is stale', function () {
          it('reverts', async function () {
            const { oevAuctionHouse, collateralRateProxy } = await helpers.loadFixture(deployAndSetUp);
            const chainId = '137';
            const bidAmount = ethers.utils.parseEther('5');
            const nextTimestamp = (await helpers.time.latest()) + 1;
            await helpers.time.setNextBlockTimestamp(nextTimestamp);
            await collateralRateProxy.mock(COLLATERAL_RATE, nextTimestamp - MAXIMUM_RATE_AGE);
            await expect(oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount))
              .to.be.revertedWithCustomError(oevAuctionHouse, 'CollateralRateIsStale')
              .withArgs();
          });
        });
      });
      context('Collateral rate is not positive', function () {
        it('reverts', async function () {
          const { oevAuctionHouse, collateralRateProxy } = await helpers.loadFixture(deployAndSetUp);
          const chainId = '137';
          const bidAmount = ethers.utils.parseEther('5');
          await collateralRateProxy.mock(0, Math.floor(Date.now() / 1000));
          await expect(oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount))
            .to.be.revertedWithCustomError(oevAuctionHouse, 'CollateralRateIsNotPositive')
            .withArgs();
        });
      });
    });
    context('Collateral rate proxy is not valid', function () {
      it('reverts', async function () {
        const { roles, oevAuctionHouse } = await helpers.loadFixture(deployAndSetUp);
        const chainId = '137';
        const bidAmount = ethers.utils.parseEther('5');
        await oevAuctionHouse.connect(roles.manager).setCollateralRateProxy(oevAuctionHouse.address);
        await expect(
          oevAuctionHouse.getCurrentCollateralAndProtocolFeeAmounts(chainId, bidAmount)
        ).to.be.revertedWithoutReason;
      });
    });
  });
});
