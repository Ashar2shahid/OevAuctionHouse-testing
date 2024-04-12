# `@api3/oev-auction-house`

```sh
# Install the dependencies
yarn
# Run the tests
yarn test
# Get test coverage at `coverage/index.html`
yarn test:coverage
```

---

[Oracle extractable value (OEV)](https://medium.com/api3/oracle-extractable-value-oev-13c1b6d53c5b) is a subset of MEV that oracles have exclusive priority of extraction.
API3 will monetize the data feed services it facilitates by holding [OEV auctions](https://github.com/api3dao/oev-litepaper/blob/main/oev-litepaper.pdf) and forwarding the proceeds to the respective user dApps.
This is both a net gain for the dApps (which otherwise would have bled these funds to MEV bots and validators), and a fair and scalable business model for first-party oracles (i.e., API providers that provide oracle services).

The API3 data feed contract (Api3ServerV1) allows two types of updates:

1. API providers publish data that is signed in a generic way.
   Anyone can [push](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/api3-server-v1/BeaconUpdatesWithSignedData.sol#L26) this data to the chain to update the respective data feed.
2. API providers sign data that can only be [used](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/api3-server-v1/OevDataFeedServer.sol#L45) by a specific account iff they also send the specified amount along with the call.

API3 facilitates OEV auctions where searchers bid for data that is specifically signed for them (i.e., type 2 updates from the above), and API3 awards the update to the highest bidder.
API3 communicates the winner to all the API provider partners, collects the signatures from them, and passes them on to the winning OEV searcher.
The winning OEV searcher is expected to use the updating calldata in a [contract](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/utils/OevSearcherMulticallV1.sol) designed to extract the OEV in a single transaction through a multicall.

To ensure effective OEV extraction, API providers should apply a slight delay (e.g., 15 seconds) to their type 1 updates.
Note that this does not have any adverse effect on the dApps that use OEV, as in the cases where there is a notable difference between `t` and `t-15` data, there will be an OEV update that will cause the dApp to see the `t` data and they will receive the OEV auction proceeds, and the absence of an OEV update would indicate that `t-15` can be considered to be equivalent to `t` in the context of the specific dApp at that point in time.
In the absence of an OEV extraction mechanism, using bare `t` data would still result in MEV extraction, which the dApp would lose out entirely on.

## Differences from MEV auctions

For the readers that are already familiar with MEV, let us point out a couple of major differences:

- MEV is typically extracted by block producers (i.e., validators or miners) auctioning away the privilege of specifying the order flow within a block.
  The searchers bid to ensure a specific order flow, which gives away their entire plan before they are awarded the order flow.
  These types of MEV auctions have to utilize sealed bids to alleviate this, which increases implementation complexity and reduces transparency.
  Note that this is not the case with OEV, as a searcher bidding 1.5 ETH for "ETH/USD being greater than or equal to 2100" would not be disclosing how they intend to utilize that update.
- MEV auctions that ensure a specific order flow through block production have the advantage of being able to bundle the bid payment in that block.
  Compared to that, unless the auction takes place on the same chain as the update is being made (which is infeasible on most chains due to the associated gas costs), it is essentially a cross-chain oracle problem to enforce winners to execute their updates.
  The obvious solution is to implement a staking mechanism at the auction platform, and slash the bidders that have won but did not execute their updates (which they may want to do as a means of denying service to other searchers).

## On-chain OEV auctions

This repo implements a contract that facilitates on-chain OEV auctions.
This is meant to address two issues:

- An OEV auction platform greatly incentivizes the participants to create, update and cancel bids at a very large volume.
  Considering that we are building the OEV auction platform for all dApps living on all chains, simply scaling up to meet this demand is not realistic, and we should have a mechanism to downregulate the demand.
  This is a long-solved problem in blockchain transactions through the gas fee, and thus hosting the auctions on-chain is an obvious solution to this problem.
- The OEV auctioneer is an oracle in essence, so it is of utmost importance for it to be able to prove a good track record.
  For this, a paper trail of the entire communication between the auctioneer and the seachers need to be kept, and a blockchain is a natural solution to this.
  Consider this for a counterexample: A searcher claims that they call the auctioneer API to make bids that should win, but the auctioneer keeps awarding the updates to other, smaller bids.
  The auctioneer would not be able to disprove this claim, as it is not possible to prove that an API call has not happened, yet whether an on-chain transaction has been sent is conclusively verifiable.

### Intended flow

The happy path for a searcher is as follows:

- The searcher deposits funds to the OevAuctionHouse contract to be used as collateral and protocol fee payment by calling `deposit()`
- The searcher places a bid by calling `placeBid()` and starts listening for awards
- An auctioneer bot periodically receives candidate OEV updates that can be awarded to bidders.
  For one of these, it goes through all active bids and determines that the highest bid is the one mentioned above.
  The auctioneer bot awards the update to the searcher by calling `awardBid()`, which also locks up respective collateral and protocol fee amounts from the searcher deposit until the fulfillment is confirmed by an auctioneer bot.
- The searcher detects the update awarded to them, and utilizing the data in `awardDetails` from `AwardedBid`, they send a transaction on another chain that pays the bid amount and extracts the OEV.
- Once the transaction above is confirmed, the searcher reports the fulfillment by calling `reportFulfillment()`, providing the transaction hash in `fulfillmentDetails`.
  The searcher has a single shot to report the fulfillment correctly, and thus should only attempt to do so once the fulfillment has reached adequate finality.
- An auctioneer bot detects the fulfillment report, checks the respective chain to confirm that the transaction hash being reported is associated with the respective OEV update being executed, and confirms the fulfillment by calling `confirmFulfillment()`, which also releases the locked up collateral and charges the protocol fee.
  The auctioneer cannot contradict a fulfillment that it has previously confirmed, and thus should only confirm it once it has reached adequate finality (which may not be the case if the searcher has reported the fulfillment prematurely).

Auctions should happen in real-time to extract OEV effectively, which is why waiting for finality at the auction platform is not ideal.
Therefore, it is recommended for OevAuctionHouse to be deployed on a chain that can sequence transactions instantly.
In case it is not, `WITHDRAWAL_WAITING_PERIOD` and `MINIMUM_BID_LIFETIME` should be increased to further protect against denial of service attacks, and the auctioneer implementation should maintain an extended award state (that includes awards from the current state of the chain and its past versions invalidated by reorgs) to avoid awarding the same OEV capture opportunity multiple times.

Even when the transaction sequencing is immediately final, any delays in sequencing may cause bids to be awarded long after the respective OEV capturing opportunity has disappeared.
Because of this, the auctioneers should send the award transactions with an `awardExpirationTimestamp` that will cause the transaction to revert if it is not sequenced right away, which will protect the bidder against unjust collateral lockups/slashings.

A potential unhappy path (for a searcher) is for an auctioneer bot to receive an update to be auctioned off that matches the conditions of the searcher, yet the searcher failing to place the highest bid.
For example, say searcher X bids $100 for ETH/USD being larger than 2100. Similarly, searcher Y bids $200 for ETH/USD being larger than 2100. In this case, the auctioneer bot will award the update to searcher Y (who will most likely execute the update, which disables searcher X from being granted exclusive rights to extract the OEV that they were targeting), in which case searcher X will no longer have a use for their bid.
The auctioneer bot will actively prune such bids that have lost against the competition so that the owners of losing bids do not need to send transactions to cancel them.
Losing bidders can still choose to call `expediteBidExpiration()` on their bids for a stronger guarantee against their losing bids being filled, yet this will not be recommended.

Another unhappy path is for a searcher to create a bid, only to find out later (while their bid is still not awarded) that the OEV opportunity that they were targeting no longer exists, e.g., they were hoping to liquidate a position, yet the owner of the position closed it before being liquidated.
In this case, the bidder needs to call `expediteBidExpiration()` explicitly, as the auctioneer bot will not be aware of the details of the OEV opportunity and will still award this bid an update when the conditions are satisfied.
As a note, we allow bid expirations to be expedited (up to 15 seconds from "now"), yet we do not allow instant cancellations.
That is to prevent searchers from frontrunning auctioneer bot award transactions with cancellations as a means of service denial.

Another unhappy path is for a searcher to be awarded an update, yet them realizing at fulfillment-time that the OEV opportunity no longer exists.
Here, the searcher needs to decide between executing the update and paying the bid amount (plus the transaction fees), or skipping the update and being slashed by the collateral amount.
In the case that the collateral requirement is less than 100% (of the bid amount), it is preferable to skip the update here.
To prevent this from being used as a service denial mechanism (in that a user keeps placing winning bids that they do not intend to fulfill), the OevAuctionHouse contract manager should maintain a large enough `collateralInBasisPoints` so that doing so is prohibitively punishing.
The thing to note here is that a `collateralInBasisPoints` that is too large increases the capital requirement for the searchers and in turn reduces searcher competition and the total amount OEV that will be extracted, and thus a minimal `collateralInBasisPoints` is preferable.

An important point to note about the cases above is that the OEV opportunity may not have disappeared coincidentally, but has been invalidated adversarially by a party to grief the OEV capture attempt.
The straightforward solution to this is submitting OEV capture transactions to private pools.

If a bidder is awarded an update and fails to report a valid fulfillment, they get slashed by an auctioneer bot calling `contradictFulfillment()`.
As mentioned above, this slashing mechanism is intended to deter against denial of service attacks.

### Auctioneer bot flow

An auction is held for a pair of chain ID and proxy address (where the [proxy address specifies both the data feed and the dApp](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/api3-server-v1/proxies/ProxyFactory.sol#L104-L105) -- or more specifically, the account that is the beneficiary of the auction proceeds, which is typically controlled by a single dApp).
A `bidTopic` is assigned to this pair, which for example could be `keccak256(abi.encodePacked(chainId, proxyAddress))` (or something less descriptive if the auctions are sealed-bid).
It is announced to the searchers that they should use this `bidTopic` while making the respective transactions, and invalid bids (that use an invalid set of `bidTopic`, `chainId` and `bidDetails`) may be slashed by a separate worker by calling `contradictFulfillment()`.
Since the auctioneer is already trusted to facilitate the auction, the contract does not enforce any rules around `bidTopic`, which reduces the gas cost and contract complexity.

An auctioneer bot does the following using a specific `bidTopic`:

- Fetches all `PlacedBid`, `ExpeditedBidExpiration` and `AwardedBid` logs from the most recent `MAXIMUM_BID_LIFETIME` and continues to periodically fetch them going forward.
- Keeps a list of active bids created out of the events from above.
  It actively prunes the bids that have expired or beaten by competitors.
- Periodically receives update candidates and awards them to the highest bidder by sending a transaction.
  It needs to check that the bidder has a sufficient balance and have not initiated a withdrawal before doing so.

In a possibly independent loop, the auctioneer does the following using a specific `bidTopic`:

- Fetches all `AwardedBid`, `ReportedFulfillment`, `ConfirmedFulfillment` and `ContradictedFulfillment` logs from the most recent `FULFILLMENT_REPORTING_PERIOD` and continues to periodically fetch them going forward.
- Keeps a list of bids awaiting fulfillment confirmation out of the events from above.
  It actively prunes bids that have received fulfillmant confirmations or contradictions.
- For the bids for which `ReportedFulfillment` is emitted (without a matching `ConfirmedFulfillment`/`ContradictedFulfillment`), it uses `fulfillmentDetails` to check if the updates have been executed on the target chains, and sends the transactions to confirm or contradict the fulfillments.
- For the bids that did not report a fulfillment in `FULFILLMENT_REPORTING_PERIOD`, sends transactions to contradict the fulfillments.

A few points:

- Note that we could have omitted `bidTopic`, and let the auctioneer bot infer it from `chainId` and `bidDetails` (which should include the proxy address).
  However, that would require each bot to fetch and index all logs, which is not optimal.
  `bidTopic` allows auctioneer bots to require much smaller RPC endpoint bandwidths and be affected less by spam transactions.
- The auctioneer bot may award an update to multiple bids of the same bidder because the update matches all bids.
  Here, the auctioneer bot may choose to enforce pre-communicated rules, such as "from each bidder, only 3 matching bids with the largest amounts will be considered."
- One potential griefing strategy in open-bid auctions is sniping, i.e., one-upping the winning bid at the last moment.
  Here, the auctioneer bot may choose to enforce pre-communicated rules, such as "winning bids that are placed in the last 5 minutes are ignored unless they increase the second best bid by at least 5%."
  Another solution to this issue is doing sealed-bid auctions by having `bidDetails` be encrypted using a public key that the respective auctioneer has announced in their documentation for searchers.
- Even though a bidder may seem to have sufficient balance at the time that the auctioneer bot sends the award transaction, it may not at the transaction confirmation time, which would cause the award transaction to revert.
  This would be caused by the bidder being awarded another update due to another bid made with another `bidTopic`, and this would be unavoidable if it was served by an independent auctioneer.
  This can be prevented by locking up bidder funds at bid-time, which would reduce their capital efficiency greatly (and thus reduce total OEV extracted), and thus was not preferred.
- In the convention that `awardDetails` is a transaction hash, the auctioneer bot will fetch the receipt of the transaction from the respective chain, and look for a matching `UpdatedOevProxyBeaconWithSignedData` or `UpdatedOevProxyBeaconSetWithSignedData` log.
  While doing so, it must only consider logs emitted by the supported Api3ServerV1 deployment on the respective chain.

#### Security implications

The auctioneer bot is trusted to facilitate the auction honestly (as an alternative to a trustless, on-chain order book, which has notorious drawbacks of its own), which enables the following unwanted scenarios:

- It can deny service (selectively or to everyone) by not awarding bids and not confirming fulfillments
- It can contradict fulfillments that have been correctly reported
- It can award bids that should have been beaten by competitors
- It can provide award details that are not valid

The purpose of doing the auctions on-chain is for such events (or their lack thereof) to be decisively provable.

Based on the fact that the scenarios above are possible, starting from the moment a bid is created and until the fulfillment is confirmed, the respective collateral is under risk of being slashed unjustly.
Note that the auctioneer role is intended to be given to a hot wallet that a bot controls, while the contract manager is intended to be a multisig.
Therefore, in the event of an unjust slashing, the funds become accessible to the multisig, and not the hot wallet.
In such an occasion, the issue is intended to be resolved retrospectively by the multisig based on the on-chain records through an off-chain dispute resolution mechanism.
An additional layer of security can be added on top of this against misconduct by the manager multisig in the form of a trustless insurance service.

#### Privileged accounts

The OevAuctionHouse contract specifies an immutable _manager_ address, which belongs to an account that has the privileges to

- Set the protocol fee and collateral requirement proportional to the bid amount
- Set the addresses of the (proxy) contracts from which the rates of the collateral currency and the native currencies (of the chains on which the OEV updates will be executed) will be read from
- Withdraw the accumulated protocol fees and slashed collateral
- Create, grant and revoke the _admin_ role

An account with the admin role can

- Renounce its admin role
- Create, grant and revoke the _proxy setter_, _withdrawer_ and _auctioneer_ roles

An account with the proxy setter role can

- Renounce its proxy setter role
- Set the addresses of the (proxy) contracts from which the rates of the collateral currency and the native currencies (of the chains on which the OEV updates will be executed) will be read from

An account with the withdrawer role can

- Renounce its withdrawer role
- Withdraw the accumulated protocol fees and slashed collateral

An account with the auctioneer role can

- Renounce its auctioneer role
- Award a bid and lock up the respective protocol fee and collateral
- Confirm the fulfillment for an awarded bid, which charges the protocol fee and releases the collateral
- Contradict the fulfillment for an awarded bid, which slashes the collateral and releases the protocol fee

Accounts with the auctioneer role are trusted to facilitate the auctions honestly, see [the section above](#security-implications) for the related security implications.

In the way that API3 intends to use this contract, the manager of OevAuctionHouse is an [OwnableCallForwarder](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/utils/OwnableCallForwarder.sol) that is owned by a Safe contract (4-of-8 at the time this is being written) that is owned by members of the API3 technical team, which are familiar with how these contracts are designed to be used and general best practices regarding controlling a wallet and interacting with a contract.
This manager account will create the contract admin role, grant it to itself, and then create the auctioneer role as a child of the admin role.
Following this, it will grant the auctioneer role to a set of EOAs that will be used by an auctioneer bot instance each.
Auctioneer bots are, in a way, oracle nodes (in that they detect on-chain oracle requests in the form of bids, do intensive off-chain computation and/or API calls to read off-chain data, and write the response back to the chain), and will be operated by the API3 technical team.
Optionally, the manager can delegate the proxy setting and withdrawing responsibilities to another account (such as a trustless contract) to streamline the respective processes.

#### Searcher flow for determining the bid amount and ensuring profitability

Consider a scenario where a searcher has detected an OEV opportunity that amounts to 100 xDAI on Gnosis Chain (if this amount changes over time, the calculations below should be repeated and the bid amount should be updated).
Assuming that there are other searchers out there that have detected the same opportunity, the said searcher should place their bid with a tight profit margin to have any chance of winning.
For argument's sake, we will assign numbers to each factor, and let's start by having the profit margin be 5%.

After the searcher has placed their bid (which costs them 0.5 xDAI) and was awarded, there are two possibilities:

1. The searcher was lucky and the OEV opportunity was still there when they were awarded (which happens 95% of the time).
   The searcher sends a transaction that captures the OEV, which includes taking out a flash loan, which cost a total of 2 xDAI.
   Then, the searcher reports their fulfillment (0.5 xDAI), and are charged the OevAuctionHouse protocol fee (10% of the bid amount).
2. The searcher found that their award no longer allows them to capture any OEV (100 - 95 = 5% probability).
   The searcher does not do anything further about this, and is slashed by the OevAuctionHouse collateral requirement (20% of the bid amount);

Let's do the math (all amounts in xDAI)

```
expectedProfit = expectedRevenue - expectedCost
oevAmount * profitMargin = successProbability * oevAmount - (placeBidTxCost + successProbability * (bidAmount + captureOevTxCost + reportFulfillmentTxCost + protocolFeeAmount) + failureProbability * collateralAmount)
100 * 0.05 = 0.95 * 100 - (0.5 + 0.95 * (bidAmount + 2 + 0.5 + 0.1 * bidAmount) + 0.05 * 0.2 * bidAmount)
5 = 95 - (0.5 + 0.95 * bidAmount + 1.9 + 0.475 + 0.095 * bidAmount + 0.01 * bidAmount)
2.875 + 1.055 * bidAmount = 90
bidAmount = 82.58
```

An important point to consider here is that an unexpected change to the collateral requirement or protocol fee will throw off the calculation.
There are two reasons why this would happen:

1. The OevAuctionHouse manager has updated the collaral requirement or protocol fee since the last time the searcher has checked them
2. The data feeds that OevAuctionHouse uses to calculate the collateral and protocol fee amounts have updated since the last time the searcher has checked them

To protect against such cases, the searcher should specify `maxCollateralAmount` and `maxProtocolFeeAmount` while sending bid placing transactions, which will cause the transaction to revert if the collateral or protocol fee amounts of the bid is beyond tolerable (i.e., profitable) limits.

An additional case to consider is that the data feeds that OevAuctionHouse uses to calculate the collateral and protocol fee amounts may misreport.
If the searcher requires protection against that, they should calculate their `maxCollateralAmount` and `maxProtocolFeeAmount` using a trusted data source.
This will cause the bid placing transactions to revert if the OevAuctionHouse data feeds are not aligned with the searcher's trusted data source.

#### On interacting with OevAuctionHouse through a contract

As with all contracts, interactions with OevAuctionHouse are originated from an EOA sending a transaction (assuming a pre-[EIP-3074](https://eips.ethereum.org/EIPS/eip-3074) world).
In the case that an EOA calls OevAuctionHouse directly, `bidder` is the address of this EOA.
This means that the EOA will be able to place bids (by calling `placeBidWithExpiration()` or `placeBid()`), report fulfillments (by calling `reportFulfillment()`), withdraw (by calling `initiateWithdrawal()` and `withdraw()` in succession), or cancel ongoing withdrawals (by calling `cancelWithdrawal()`).

In case that the user wants to limit the privileges of the EOA that interacts with OevAuctionHouse, they can implement a contract that forwards calls to OevAuctionHouse bounded by specific rules.
As a toy example, say we have lended our capital to a searcher bot operator to capture OEV on our behalf.
However, we do not want the bot operator to be able to withdraw our capital.
We could implement a contract that forwards the `placeBidWithExpiration()`, `placeBid()` and `reportFulfillment()` calls from the bot operator EOA, and the `initiateWithdrawal()`, `withdraw()` and `cancelWithdrawal()` calls from our EOA.
(As a note, this does not prevent the bot operator from burning through the funds by placing invalid bids, nor does it guarantee that the bot operator will share the revenue, which is why this is called a toy example.)

Below are the important points to consider while implementing a contract that calls `placeBidWithExpiration()` and/or `placeBid()`:

- `reportFulfillment()` has to be called by the same account that has placed the bid.
  Therefore, one should design a flow that has the same contract report the respective fulfillments.
- `initiateWithdrawal()` and `withdraw()` has to be called by the same account for which funds were deposited (which is also the account that places the bids).
  Therefore, one should design a flow that has the same contract calls the `initiateWithdrawal()` and `withdraw()` functions in succession to withdraw funds.
  Optionally, `cancelWithdrawal()` support may be implemented.
- The withdrawal recipient is specified in the `withdraw()` call.
  In the case that the recipient is the said contract, it should be `payable` (to execute the withdrawal), and allow funds in the native currency be withdrawn from it.
- Although it may seem like `withdraw()` is the only critical withdrawal-related call because it specifies the recipient and amount, `initiateWithdrawal()` and `cancelWithdrawal()` are also risky to expose.
  For example, a malicious actor that has access to it may call `initiateWithdrawal()` so that the auctioneer bots disregard the respective bids, or call `cancelWithdrawal()` whenever a withdrawal is initiated to prevent the funds from ever being withdrawn.
  Therefore, the said contract should only expose these functions to a trusted EOA or multisig, or in the case that it will expose them to untrusted parties in a restricted fashion, great care must be taken to make sure that doing so will not be abused.

## Expected Contract Load and Usage

- `deposit()`:
    - used by: `SEARCHER`
    - expected load: 1 request per min
    - description: searchers will use this function to    deposit funds to the contract infrequently
- `placeBid()`:
    - used by: `SEARCHER`
    - expected load: 30 request per sec
    - description: searchers will use this function to place bids to the contract frequently. This function is expected to be called by a large number of searchers especially when there is an OEV opportunity.
- `awardBid()`:
    - used by: `AUCTIONEER`
    - expected load: 20 request per min
    - description: auctioneer bots will use this function to award bids to the searchers frequently. The fulfillment of this function call is critical for the searcher to extract the OEV and hence shouldn't be delayed or bottlenecked.
- `reportFulfillment()`:
    - used by: `SEARCHER`
    - expected load: 10 request per min
    - description: searchers will use this function to report the fulfillment of the OEV transaction. This function is expected to be called frequently.
- `confirmFulfillment()`:
    - used by: `AUCTIONEER`
    - expected load: 10 request per min
    - description: auctioneer bots will use this function to confirm the fulfillment of the OEV transaction. This function is expected to be called frequently.
  


## Example conventions for `bidDetails`, `awardDetails` and `fulfillmentReport`

Below are example conventions for `bidDetails`, `awardDetails` and `fulfillmentReport`.
The finalized conventions will be documented in the user-facing docs.

### `bidDetails`

The bid placement transaction specifies the chain ID and the bid amount, which means that all the remaining parameters have to be specified in the bid details in a way that the auctioneer bot can decode.
These parameters are:

- `proxyWithOevAddress`: Address of the DapiProxyWithOev or DataFeedProxyWithOev contract through which the OEV update will be readable
- `conditionType`: 0, which means less-than-or-equal-to, and 1, which means greater-than-or-equal-to
- `conditionValue`: The value that will be compared with the data feed value to decide if the condition is satisfied
- `updateSenderAddress`: The `msg.sender` address that the Api3ServerV1 contract will see while `updateOevProxyDataFeedWithSignedData()` is being called to execute the OEV update

The unique bid ID is derived as `keccak256(abi.encodePacked(bidderAddress, bidTopic, keccak256(bidDetails)))`.
Note that a bidder may want to place a bid with the parameters above twice, which means that the bid ID will be the same.
To avoid this, the bidder should include a unique nonce to `bidDetails`.

The bid details can then be encoded as follows:

```js
ethers.utils.defaultAbiCoder.encode(
  ['address', 'uint256', 'int224', 'address', 'bytes32'],
  [
    proxyWithOevAddress,
    conditionType,
    conditionValue,
    updateSenderAddress,
    ethers.utils.hexlify(ethers.utils.randomBytes(32)),
  ]
);
```

Finally, if the auctioneer has specified that the encoded bid details should/must be encrypted, the searcher does the encryption as documented, for example, using AES-256 with the public key that the auctioneer has announced.

### `awardDetails`

The award details should include adequate information for the searcher to be able to capture the awarded OEV opportunity.
This is done by multi-calling `Api3ServerV1.updateOevProxyDataFeedWithSignedData()` to update the data feed, along with additional calls that capture the OEV.

The signature of the `updateOevProxyDataFeedWithSignedData()` function is

```solidity
function updateOevProxyDataFeedWithSignedData(
  address oevProxy,
  bytes32 dataFeedId,
  bytes32 updateId,
  uint256 timestamp,
  bytes calldata data,
  bytes[] calldata packedOevUpdateSignatures
) external payable;
```

where each `packedOevUpdateSignatures` item can be decoded as

```solidity
(address airnode, bytes32 templateId, bytes memory signature) = abi.decode(packedOevUpdateSignature, (address, bytes32, bytes));
```

The most user-friendly convention for `awardDetails` would be the encoded calldata that the searcher can call Api3ServerV1 directly with.
One thing to consider is that the auctioneer may want to encrypt `awardDetails` in a way that only the awarded bidder can decrypt it to keep the OEV capture attempt more private.
This would require bidders to announce a public key beforehand.

### `fulfillmentReport`

The auctioneer already has a chain ID associated with each bid ID, and thus the searcher reporting the hash of the OEV update transaction is adequate for the auctioneer to be able to confirm that the OEV update has been executed.
Nevertheless, `fulfillmentReport` is underdefined as the `bytes` type to support more complex fulfillment report schemas as necessary.

## External contract glossary

### [AccessControlRegistry](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/access-control-registry/AccessControlRegistry.sol)

An [AccessManager](https://docs.openzeppelin.com/contracts/5.x/api/access#accessmanager)-equivalent that API3 uses to manage its access control rules

### [AccessControlRegistryAdminnedWithManager](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/access-control-registry/AccessControlRegistryAdminnedWithManager.sol)

The contract that is inherited by contracts whose access control rules are to be managed by AccessControlRegistry.
The inheriting contract will have an immutable `manager` account (which can be thought of as a super admin), under which the contract may define additional roles.
This contract also inherits [SelfMulticall](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/utils/SelfMulticall.sol) for user convenience.

### [Api3ServerV1](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/api3-server-v1/Api3ServerV1.sol)

The contract that houses the data feeds updated by API3's Airnode protocol.
Although these data feeds can be read by calling Api3ServerV1 directly, the users are recommended to read them through proxy contracts, which provide a simple and standard interface.

### [IProxy](https://github.com/api3dao/airnode-protocol-v1/blob/main/contracts/api3-server-v1/proxies/interfaces/IProxy.sol)

The interface of a generic proxy contract that API3 users are recommended to use to read a specific data feed.

