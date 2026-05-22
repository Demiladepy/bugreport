// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {BaseSettlement} from "solidity/settlement/contracts/BaseSettlement.sol";

/// @notice Minimal mock for ISettlementSignatureVerifier dependency
contract MockSignatureVerifier {
    mapping(address => bool) public validators;
    
    function add_validator(address validator) external {
        validators[validator] = true;
    }
    
    function remove_validator(address validator) external {
        validators[validator] = false;
    }
}

/// @notice Concrete implementation of BaseSettlement for testing since it's abstract
contract ConcreteSettlement is BaseSettlement {
    function initialize(
        string memory _chain_name,
        uint256 _chain_id,
        address _owner,
        address[] memory _managers,
        uint256 _required_validators,
        address _signature_verifier
    ) external {
        _Settlement_init(
            _chain_name,
            _chain_id,
            _owner,
            _managers,
            _required_validators,
            _signature_verifier
        );
    }
}

contract Test2024_08_chakra_missing_access_control_in_settlement_ini is Test, SymTest {
    ConcreteSettlement settlement;
    MockSignatureVerifier signatureVerifier;
    address owner;
    address attacker;

    function setUp() public {
        owner = address(0x1111);
        attacker = address(0x2222);
        
        signatureVerifier = new MockSignatureVerifier();
        settlement = new ConcreteSettlement();
        
        // Initialize the contract with owner
        address[] memory managers = new address[](1);
        managers[0] = address(0x3333);
        
        vm.prank(owner);
        settlement.initialize(
            "TestChain",
            1,
            owner,
            managers,
            2,
            address(signatureVerifier)
        );
    }

    /// @notice Property: After initialization, _Settlement_init MUST NOT be callable by unauthorized users
    /// @dev On FIXED code (with proper access control/initializer modifier), this should PASS (revert on reinit)
    /// @dev On VULNERABLE code (missing access control), this will FAIL (reinit succeeds)
    function check_settlement_init_cannot_be_reinitialized() public {
        // Verify contract is already initialized - owner should be set
        address currentOwner = settlement.owner();
        assert(currentOwner == owner);
        
        // Attacker attempts to reinitialize with themselves as owner
        address[] memory maliciousManagers = new address[](1);
        maliciousManagers[0] = attacker;
        
        vm.prank(attacker);
        
        // Try to call _Settlement_init directly (it's public in vulnerable code)
        // On fixed code: should revert due to initializer modifier or access control
        // On vulnerable code: will succeed, allowing attacker to become owner
        (bool success,) = address(settlement).call(
            abi.encodeWithSignature(
                "_Settlement_init(string,uint256,address,address[],uint256,address)",
                "MaliciousChain",
                999,
                attacker,
                maliciousManagers,
                1,
                address(signatureVerifier)
            )
        );
        
        // The property: reinitialization by attacker MUST fail
        // If this assertion fails, the vulnerability exists (attacker could reinitialize)
        assert(!success);
    }
}
