// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {EntropyGenerator} from "contracts/EntropyGenerator/EntropyGenerator.sol";

contract Test2024_07_traitforge_H_1 is Test, SymTest {
    EntropyGenerator entropyGenerator;
    address owner;
    address traitForgeNft;

    function setUp() public {
        owner = address(this);
        traitForgeNft = makeAddr("traitForgeNft");
        
        // Deploy the EntropyGenerator contract
        // The deployer (this contract) becomes the owner via Ownable
        entropyGenerator = new EntropyGenerator(traitForgeNft);
    }

    /// @notice Verifies that the owner can call pause() to pause the contract
    /// @dev The finding states that EntropyGenerator inherits Pausable but doesn't expose
    ///      public pause()/unpause() functions. This test checks if pause() is callable.
    ///      On VULNERABLE code: pause() doesn't exist, so the call will fail and assert(false) triggers
    ///      On FIXED code: pause() exists and succeeds, paused() returns true
    function check_pause_function_exists() public {
        // Attempt to call pause() as the owner
        // Using low-level call to check if the function exists
        (bool success,) = address(entropyGenerator).call(
            abi.encodeWithSignature("pause()")
        );
        
        // If the call fails, the pause function doesn't exist or isn't callable by owner
        // This would be the vulnerable state
        if (!success) {
            // Vulnerable: pause() function is not accessible
            assert(false);
        }
        
        // If we reach here, pause() succeeded
        // Verify the contract is actually paused
        bool isPaused = entropyGenerator.paused();
        assert(isPaused == true);
    }
}
