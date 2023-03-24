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
