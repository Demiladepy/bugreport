// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {ConfigurablePause} from "src/ConfigurablePause.sol";

/// @notice Test harness that exposes internal _updatePauseDuration for testing
contract ConfigurablePauseHarness is ConfigurablePause {
    /// @notice Expose internal _updatePauseDuration for testing
    function updatePauseDuration(uint128 newPauseDuration) external {
        _updatePauseDuration(newPauseDuration);
    }

    /// @notice Expose internal _setPauseTime for setup
    function setPauseTime(uint128 newPauseStartTime) external {
        _setPauseTime(newPauseStartTime);
    }

    /// @notice Expose internal _grantGuardian for setup
    function grantGuardian(address newPauseGuardian) external {
        _grantGuardian(newPauseGuardian);
    }

    /// @notice Set pauseDuration directly for testing
    function setInitialPauseDuration(uint128 duration) external {
        pauseDuration = duration;
    }
}

contract Test2024_10_kleidi_missing_pause_time_checks_in_updatepause is Test, SymTest {
    ConfigurablePauseHarness target;

    function setUp() public {
        target = new ConfigurablePauseHarness();
    }

    /// @notice Property: _updatePauseDuration MUST revert when the contract is currently paused
    /// The vulnerability is that calling _updatePauseDuration while paused resets pauseStartTime to 0,
    /// effectively unpausing the contract unexpectedly.
    /// On FIXED code (with whenNotPaused modifier), this should PASS (revert when paused).
    /// On VULNERABLE code (without check), this should FAIL (does not revert when paused).
    function check_updatePauseDuration_reverts_when_paused() public {
        // Setup symbolic values
        uint128 currentPauseStart = uint128(svm.createUint(128, "currentPauseStart"));
        uint128 currentPauseDuration = uint128(svm.createUint(128, "currentPauseDuration"));
        uint128 newPauseDuration = uint128(svm.createUint(128, "newPauseDuration"));
        uint256 timestamp = svm.createUint(256, "timestamp");

        // Constrain: pauseStartTime != 0 (contract has been paused)
        vm.assume(currentPauseStart != 0);
        
        // Constrain: pauseDuration is within valid bounds for the setup
        vm.assume(currentPauseDuration >= target.MIN_PAUSE_DURATION());
        vm.assume(currentPauseDuration <= target.MAX_PAUSE_DURATION());
        
        // Constrain: we are within the pause window (contract is paused)
        // paused() returns true when: block.timestamp <= pauseStartTime + pauseDuration
        vm.assume(timestamp <= uint256(currentPauseStart) + uint256(currentPauseDuration));
        
        // Constrain: newPauseDuration is within valid bounds (so it won't revert for that reason)
        vm.assume(newPauseDuration >= target.MIN_PAUSE_DURATION());
        vm.assume(newPauseDuration <= target.MAX_PAUSE_DURATION());

        // Set the block timestamp
        vm.warp(timestamp);

        // Setup contract state: paused
        target.setInitialPauseDuration(currentPauseDuration);
        target.setPauseTime(currentPauseStart);

        // Verify precondition: contract is paused
        assert(target.paused());

        // Action: attempt to update pause duration while paused
        // This SHOULD revert on fixed code (with whenNotPaused modifier)
        // but DOES NOT revert on vulnerable code
        (bool success,) = address(target).call(
            abi.encodeWithSelector(ConfigurablePauseHarness.updatePauseDuration.selector, newPauseDuration)
        );

        // Property: when paused, updatePauseDuration must revert (success should be false)
        // If success is true, the vulnerability exists - pause was bypassed
        assert(!success);
    }
}
