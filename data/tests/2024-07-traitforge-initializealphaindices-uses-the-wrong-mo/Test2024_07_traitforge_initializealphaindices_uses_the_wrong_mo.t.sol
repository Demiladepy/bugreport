// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {EntropyGenerator} from "contracts/EntropyGenerator/EntropyGenerator.sol";

contract Test2024_07_traitforge_initializealphaindices_uses_the_wrong_mo is Test, SymTest {
    EntropyGenerator entropyGenerator;
    address owner;
    address allowedCaller;

    function setUp() public {
        owner = address(this);
        allowedCaller = makeAddr("traitForgeNft");
        
        // Deploy EntropyGenerator with allowedCaller as the TraitForgeNft address
        entropyGenerator = new EntropyGenerator(allowedCaller);
    }

    /// @notice Test that initializeAlphaIndices should be callable by allowedCaller
    /// @dev BUG: The function uses onlyOwner modifier but should use onlyAllowedCaller
    ///      The TraitForgeNft contract (allowedCaller) needs to call this during _incrementGeneration
    ///      but it will revert because only the owner can call it
    function check_initializeAlphaIndices_callable_by_allowedCaller() public {
        // Verify our setup: allowedCaller is set correctly and is not the owner
        address currentAllowedCaller = entropyGenerator.getAllowedCaller();
        assert(currentAllowedCaller == allowedCaller);
        assert(allowedCaller != entropyGenerator.owner());
        assert(allowedCaller != address(0));
        
        // The allowedCaller (TraitForgeNft) should be able to call initializeAlphaIndices
        // This is needed when _incrementGeneration is called during minting
        vm.prank(allowedCaller);
        (bool success,) = address(entropyGenerator).call(
            abi.encodeWithSelector(EntropyGenerator.initializeAlphaIndices.selector)
        );
        
        // FIXED CODE: This assertion should PASS (success == true)
        // VULNERABLE CODE: This assertion will FAIL because onlyOwner blocks allowedCaller
        assert(success);
    }
}
