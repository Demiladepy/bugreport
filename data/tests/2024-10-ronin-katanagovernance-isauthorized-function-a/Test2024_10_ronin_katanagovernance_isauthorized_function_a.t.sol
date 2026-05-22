// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {KatanaGovernance} from "src/governance/KatanaGovernance.sol";

contract Test2024_10_ronin_katanagovernance_isauthorized_function_a is Test, SymTest {
    KatanaGovernance governance;
    address admin;
    address testAccount;
    
    // Constants from KatanaGovernance
    uint256 constant UNAUTHORIZED = 0;
    uint256 constant AUTHORIZED = type(uint256).max;

    function setUp() public {
        admin = makeAddr("admin");
        testAccount = makeAddr("testAccount");
        
        // Deploy KatanaGovernance - it's upgradeable so we need to initialize
        governance = new KatanaGovernance();
        
        // Initialize the contract with admin
        governance.initialize(admin, address(0));
    }

    /// @notice Test that authorization expires correctly when block.timestamp >= expiry
    /// @dev The bug is that _isAuthorized returns true when block.timestamp > expiry instead of false
    /// The condition uses '>' when it should use '<', allowing actions after expiry
    function check_isAuthorized_respects_expiry() public {
        // Create symbolic values for expiry time and current block time
        uint256 expiry = svm.createUint256("expiry");
        uint256 blockTime = svm.createUint256("blockTime");
        
        // Constrain: expiry is not UNAUTHORIZED (0) and not AUTHORIZED (type(uint256).max)
        vm.assume(expiry != UNAUTHORIZED);
        vm.assume(expiry != AUTHORIZED);
        
        // Constrain: block timestamp is at or after expiry (authorization should have expired)
        vm.assume(blockTime >= expiry);
        
        // Ensure reasonable bounds to avoid overflow issues
        vm.assume(expiry > 0);
        vm.assume(expiry < type(uint256).max - 1);
        vm.assume(blockTime < type(uint256).max);
        
        // Set block timestamp to be at or after expiry
        vm.warp(blockTime);
        
        // As admin, set a permission that will expire
        // We use setPermission to grant temporary access that expires at 'expiry'
        vm.prank(admin);
        governance.setPermission(testAccount, expiry);
        
        // Now check if the account is still authorized (it shouldn't be after expiry)
        // We can check this by trying to call a permissioned function
        // The isAuthorized function is internal, so we test via external behavior
        
        // Get the permission state - if the bug exists, the account will still be authorized
        // even though block.timestamp >= expiry
        
        // Since _isAuthorized is internal, we test via the external interface
        // We check if an account with expired permission can still act as authorized
        
        // The permission was set to expire at 'expiry', and current time is >= expiry
        // So calling setPermission from testAccount should fail (as they're not authorized)
        
        // Actually, let's test via checking if the account can call a restricted function
        // If the bug exists: account is still authorized after expiry
        // If fixed: account is not authorized after expiry
        
        // We test by checking the effective authorization state
        // When expiry time has passed, any call that relies on _isAuthorized should fail
        
        // Since we can't directly call _isAuthorized, we verify the invariant:
        // After expiry, the account should NOT be considered authorized
        
        // We use a try/catch to check if a permissioned action succeeds
        // testAccount should NOT be able to perform admin actions after expiry
        
        vm.prank(testAccount);
        try governance.setPermission(address(0x123), 1000) {
            // If this succeeds, the account is still authorized (BUG!)
            // After expiry, this should have reverted
            assert(false); // Bug exists: should have been unauthorized
        } catch {
            // Expected behavior: account is not authorized after expiry
            assert(true);
        }
    }
    
    /// @notice Simpler test: verify that temporary permission doesn't persist after expiry
    function check_permission_expires_at_timestamp() public {
        uint256 expiryTime = 1000;
        uint256 afterExpiry = 1001;
        
        // Grant temporary permission to testAccount
        vm.prank(admin);
        governance.setPermission(testAccount, expiryTime);
        
        // Move time past expiry
        vm.warp(afterExpiry);
        
        // testAccount should not be authorized anymore
        // If they can call a restricted function, the bug exists
        vm.prank(testAccount);
        try governance.setPermission(address(0x456), 2000) {
            // Bug: permission should have expired but action succeeded
            assert(false);
        } catch {
            // Correct: permission expired, action denied
            assert(true);
        }
    }
}
