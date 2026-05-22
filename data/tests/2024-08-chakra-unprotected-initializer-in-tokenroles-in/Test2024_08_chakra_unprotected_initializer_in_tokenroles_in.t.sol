// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TokenRoles} from "solidity/handler/contracts/TokenRoles.sol";

/// @dev Concrete implementation of the abstract TokenRoles contract for testing
contract ConcreteTokenRoles is TokenRoles {
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
    
    /// @dev Expose initialization for testing
    function initialize(address _owner, address _operator) external {
        __TokenRoles_init(_owner, _operator);
    }
}

contract Test2024_08_chakra_unprotected_initializer_in_tokenroles_in is Test, SymTest {
    ConcreteTokenRoles tokenRoles;

    function setUp() public {
        tokenRoles = new ConcreteTokenRoles();
    }

    /// @notice Verifies that __TokenRoles_init reverts when called a second time
    /// @dev On FIXED code: second call should revert (assertion passes)
    /// @dev On VULNERABLE code: second call succeeds, assertion fails
    function check_reinitializationReverts() public {
        address owner1 = svm.createAddress("owner1");
        address op1 = svm.createAddress("op1");
        address owner2 = svm.createAddress("owner2");
        address op2 = svm.createAddress("op2");
        
        // Ensure distinct addresses to avoid trivial cases
        vm.assume(owner1 != address(0));
        vm.assume(op1 != address(0));
        vm.assume(owner2 != address(0));
        vm.assume(op2 != address(0));
        
        // First initialization should succeed
        tokenRoles.__TokenRoles_init(owner1, op1);
        
        // Second initialization MUST revert on fixed code
        // On vulnerable code, this call will succeed and the assertion will fail
        bool secondInitSucceeded;
        try tokenRoles.__TokenRoles_init(owner2, op2) {
            secondInitSucceeded = true;
        } catch {
            secondInitSucceeded = false;
        }
        
        // Assert that reinitialization failed (should be true on fixed code)
        assert(!secondInitSucceeded);
    }
}
