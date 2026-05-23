// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {KatanaGovernance} from "src/governance/KatanaGovernance.sol";

contract MockV2Factory {
    function allowedAll() external pure returns (bool) {
        return false;
    }

    function allPairsLength() external pure returns (uint256) {
        return 0;
    }

    function allPairs(uint256) external pure returns (address) {
        return address(0);
    }
}

/// @dev Curated Halmos test: after whitelist expiry, arbitrary accounts must not be authorized.
contract Test2024_10_ronin_katanagovernance_isauthorized_function_a is Test, SymTest {
    KatanaGovernance governance;
    address admin;
    address allowedAccount;
    address outsider;

    function setUp() public {
        admin = makeAddr("admin");
        allowedAccount = makeAddr("allowed");
        outsider = makeAddr("outsider");
        governance = new KatanaGovernance();
        governance.initialize(admin, address(new MockV2Factory()));
    }

    /// @dev FAIL on vulnerable commit (expired whitelist authorizes arbitrary outsider).
    /// @dev PASS on fixed commit (outsider remains unauthorized after expiry).
    function check_expired_whitelist_does_not_authorize_outsider() public {
        address token = makeAddr("token");
        uint40 expiryTime = uint40(svm.createUint256("expiry"));
        uint256 afterExpiry = svm.createUint256("afterExpiry");
        vm.assume(expiryTime > 0);
        vm.assume(expiryTime < type(uint40).max);
        vm.assume(afterExpiry >= expiryTime);
        vm.assume(afterExpiry < type(uint256).max);
        vm.assume(outsider != admin);
        vm.assume(outsider != allowedAccount);

        address[] memory alloweds = new address[](1);
        alloweds[0] = allowedAccount;
        bool[] memory statuses = new bool[](1);
        statuses[0] = true;

        vm.prank(admin);
        governance.setPermission(token, expiryTime, alloweds, statuses);

        vm.warp(afterExpiry);

        assert(!governance.isAuthorized(token, outsider));
    }
}
