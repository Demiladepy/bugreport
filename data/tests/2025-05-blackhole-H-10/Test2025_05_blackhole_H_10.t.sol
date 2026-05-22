// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {SetterTopNPoolsStrategy} from "contracts/SetterTopNPoolsStrategy.sol";

/// @notice Minimal AVM stub for SetterTopNPoolsStrategy constructor (dependency, not target).
contract MockAVM {
    uint256 public topN;
    address public executor;

    constructor(address _executor, uint256 _topN) {
        executor = _executor;
        topN = _topN;
    }
}

/// @notice Halmos test: owner MUST be able to call setTopNPools.
contract Test2025_05_blackhole_H_10 is Test, SymTest {
    SetterTopNPoolsStrategy strategy;
    address owner;
    address executor;

    function setUp() public {
        owner = makeAddr("owner");
        executor = makeAddr("executor");
        MockAVM avm = new MockAVM(executor, 10);
        vm.prank(owner);
        strategy = new SetterTopNPoolsStrategy(makeAddr("voter"), address(avm));
    }

    /// @dev FAIL on vulnerable commit (onlyExecutor blocks owner).
    /// @dev PASS on fixed commit (onlyOwnerOrExecutor allows owner).
    function check_ownerCanSetTopNPools() public {
        vm.assume(owner != executor);
        address[] memory pools = new address[](0);

        vm.prank(owner);
        (bool success,) = address(strategy).call(
            abi.encodeWithSelector(SetterTopNPoolsStrategy.setTopNPools.selector, pools)
        );

        assert(success);
    }
}
