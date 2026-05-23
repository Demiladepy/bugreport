// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @dev Curated Halmos test: deploy 0.7.6 NFPM via deployCode to avoid mixed-pragma imports.
contract Test2024_10_ronin_missing_authorization_check_in_increasel is Test, SymTest {
    address nfpm;
    address owner;

    function setUp() public {
        address factory = address(new MockFactory());
        address weth = address(new MockWETH());
        nfpm = deployCode(
            "src/periphery/NonfungiblePositionManager.sol:NonfungiblePositionManager",
            abi.encode(factory, weth, address(0))
        );
        owner = makeAddr("owner");
    }

    /// @dev FAIL on vulnerable commit (unauthorized caller succeeds).
    /// @dev PASS on fixed commit (unauthorized caller reverts).
    function check_increaseLiquidity_unauthorized() public {
        address caller = svm.createAddress("caller");
        vm.assume(caller != address(0));
        vm.assume(caller != owner);

        bytes memory callData = abi.encodeWithSignature(
            "increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))",
            uint256(1),
            uint256(1000),
            uint256(1000),
            uint256(0),
            uint256(0),
            block.timestamp + 1000
        );

        vm.prank(caller);
        (bool success,) = nfpm.call(callData);
        assert(!success);
    }
}

contract MockWETH {
    function deposit() external payable {}
}

contract MockFactory {
    address public pool;

    function setPool(address _pool) external {
        pool = _pool;
    }

    function getPool(address, address, uint24) external view returns (address) {
        return pool;
    }
}
