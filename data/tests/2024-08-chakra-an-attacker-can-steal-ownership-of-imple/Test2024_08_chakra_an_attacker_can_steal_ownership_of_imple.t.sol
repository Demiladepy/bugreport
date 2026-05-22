// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {SettlementSignatureVerifier} from "solidity/handler/contracts/SettlementSignatureVerifier.sol";

contract Test2024_08_chakra_an_attacker_can_steal_ownership_of_imple is Test, SymTest {
    SettlementSignatureVerifier implementation;

    function setUp() public {
        // Deploy implementation contract directly (not via proxy)
        // This simulates the implementation contract being deployed
        implementation = new SettlementSignatureVerifier();
    }

    /// @notice Test that initialize cannot be called directly on the implementation contract
    /// @dev On vulnerable code: initialize succeeds, attacker becomes owner -> assert fails (Halmos FAIL)
    /// @dev On fixed code: initialize reverts due to _disableInitializers() in constructor -> assert passes (Halmos PASS)
    function check_implementationCannotBeInitialized() public {
        address attacker = svm.createAddress("attacker");
        uint256 requiredValidators = svm.createUint256("requiredValidators");
        
        // Assume reasonable bounds for symbolic values
        vm.assume(attacker != address(0));
        vm.assume(requiredValidators > 0 && requiredValidators < 100);

        // Attacker attempts to call initialize directly on implementation
        vm.prank(attacker);
        (bool success,) = address(implementation).call(
            abi.encodeWithSelector(
                SettlementSignatureVerifier.initialize.selector,
                attacker,
                requiredValidators
            )
        );

        // On fixed code: _disableInitializers() in constructor prevents initialization
        // so success should be false (call reverts)
        // On vulnerable code: no _disableInitializers(), so initialize succeeds
        // and attacker becomes owner
        assert(!success);
    }
}
