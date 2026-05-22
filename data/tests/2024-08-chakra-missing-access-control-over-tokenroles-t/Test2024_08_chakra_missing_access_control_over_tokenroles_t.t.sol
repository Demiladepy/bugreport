// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TokenRoles} from "solidity/handler/contracts/TokenRoles.sol";

/// @dev Concrete implementation of the abstract TokenRoles contract for testing
contract ConcreteTokenRoles is TokenRoles {
    function initialize(address _owner, address _operator) external {
        __TokenRoles_init(_owner, _operator);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract Test2024_08_chakra_missing_access_control_over_tokenroles_t is Test, SymTest {
    ConcreteTokenRoles tokenRoles;

    function setUp() public {
        tokenRoles = new ConcreteTokenRoles();
    }

    /// @notice Property: __TokenRoles_init MUST revert when called after the contract has already been initialized
    /// @dev On FIXED code: second init call should revert (test PASSES)
    /// @dev On VULNERABLE code: second init call succeeds, changing owner (test FAILS)
    function check_tokenRolesInit_cannotReinitialize() public {
        // Create symbolic addresses for two initialization attempts
        address owner1 = svm.createAddress("owner1");
        address operator1 = svm.createAddress("operator1");
        address owner2 = svm.createAddress("owner2");
        address operator2 = svm.createAddress("operator2");

        // Ensure addresses are valid (non-zero) and different between init attempts
        vm.assume(owner1 != address(0));
        vm.assume(operator1 != address(0));
        vm.assume(owner2 != address(0));
        vm.assume(operator2 != address(0));
        vm.assume(owner1 != owner2);

        // First initialization - should succeed
        tokenRoles.__TokenRoles_init(owner1, operator1);

        // Store the owner after first initialization
        address ownerAfterFirstInit = tokenRoles.owner();

        // Attempt second initialization using low-level call to catch revert
        (bool success,) = address(tokenRoles).call(
            abi.encodeWithSelector(TokenRoles.__TokenRoles_init.selector, owner2, operator2)
        );

        // Property: Re-initialization must fail (success should be false)
        // On FIXED code: success == false, so assertion holds
        // On VULNERABLE code: success == true, so assertion fails
        assert(!success);

        // Additionally verify owner was not changed
        assert(tokenRoles.owner() == ownerAfterFirstInit);
    }
}
