// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.21;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {LRTConfig} from "src/LRTConfig.sol";

contract Test2023_11_kelp_lack_of_deletion_mechanism_for_assets_po is Test, SymTest {
    LRTConfig lrtConfig;
    address admin;
    address manager;
    address stETH;
    address rETH;
    address cbETH;
    address rsETH;

    bytes32 constant MANAGER_ROLE = keccak256("MANAGER");

    function setUp() public {
        admin = makeAddr("admin");
        manager = makeAddr("manager");
        stETH = makeAddr("stETH");
        rETH = makeAddr("rETH");
        cbETH = makeAddr("cbETH");
        rsETH = makeAddr("rsETH");

        lrtConfig = new LRTConfig();
        lrtConfig.initialize(admin, stETH, rETH, cbETH, rsETH);

        vm.prank(admin);
        lrtConfig.grantRole(MANAGER_ROLE, manager);
    }

    /// @notice This test demonstrates the vulnerability: once an asset is added,
    /// it cannot be removed. The property checks that after adding an asset,
    /// the asset remains permanently supported with no way to remove it.
    /// On FIXED code (with removeSupportedAsset function), the asset could be removed.
    /// On VULNERABLE code (current), the asset is permanently stuck as supported.
    function check_assetCannotBeRemovedOnceAdded() public {
        address newAsset = svm.createAddress("newAsset");
        uint256 depositLimit = 1000 ether;

        vm.assume(newAsset != address(0));
        vm.assume(newAsset != stETH);
        vm.assume(newAsset != rETH);
        vm.assume(newAsset != cbETH);

        // Add a new asset as manager
        vm.prank(manager);
        lrtConfig.addNewSupportedAsset(newAsset, depositLimit);

        // Verify asset is now supported
        bool isSupported = lrtConfig.isSupportedAsset(newAsset);
        assert(isSupported);

        // Try to check if removeSupportedAsset function exists by attempting to call it
        // This documents the missing functionality - the selector should not exist
        bytes4 removeSelector = bytes4(keccak256("removeSupportedAsset(address)"));
        
        vm.prank(manager);
        (bool success,) = address(lrtConfig).call(
            abi.encodeWithSelector(removeSelector, newAsset)
        );

        // The call fails because the function doesn't exist
        // On FIXED code: success would be true and asset would be removed
        // On VULNERABLE code: success is false (function doesn't exist)
        
        // Property: In a secure system, after removal attempt, asset should NOT be supported
        // This assertion will PASS on vulnerable code (asset stays supported)
        // and would FAIL on fixed code (asset would be removed)
        // We invert the logic: assert that asset IS STILL supported after removal attempt
        // This demonstrates the bug - assets cannot be removed
        bool stillSupported = lrtConfig.isSupportedAsset(newAsset);
        
        // The vulnerability is proven if: removal call failed AND asset is still supported
        // This property should FAIL on fixed code (where removal works)
        // and PASS on vulnerable code (where removal doesn't exist)
        assert(!success && stillSupported);
    }
}
