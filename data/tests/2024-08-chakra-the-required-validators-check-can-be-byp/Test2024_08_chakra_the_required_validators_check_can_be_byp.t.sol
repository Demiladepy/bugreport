// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {SettlementSignatureVerifier} from "solidity/settlement/contracts/SettlementSignatureVerifier.sol";

contract Test2024_08_chakra_the_required_validators_check_can_be_byp is Test, SymTest {
    SettlementSignatureVerifier verifier;
    address owner;
    address manager;
    address validator1;
    uint256 validator1PrivateKey;
    
    uint256 constant REQUIRED_VALIDATORS = 2;

    function setUp() public {
        owner = makeAddr("owner");
        manager = makeAddr("manager");
        
        // Create a validator with known private key for signing
        validator1PrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        validator1 = vm.addr(validator1PrivateKey);
        
        // Deploy the verifier through proxy initialization pattern
        verifier = new SettlementSignatureVerifier();
        verifier.initialize(owner, REQUIRED_VALIDATORS);
        
        // Add manager
        vm.prank(owner);
        verifier.add_manager(manager);
        
        // Add only ONE validator (but we require 2)
        vm.prank(manager);
        verifier.add_validator(validator1);
    }

    /// @notice Property: verifyECDSA must reject when the same validator signs multiple times
    /// If only 1 unique validator signed but required_validators is 2, verification should fail
    /// The vulnerability allows bypassing this by submitting duplicate signatures
    function check_duplicateSignaturesShouldNotPassVerification() public {
        bytes32 msgHash = keccak256("test message");
        
        // Sign the message with validator1's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1PrivateKey, msgHash);
        bytes memory sig1 = abi.encodePacked(r, s, v);
        
        // Create signatures array with the SAME signature duplicated
        // This should NOT pass because we only have 1 unique validator
        // but the vulnerable code counts the same validator twice
        bytes memory duplicatedSignatures = abi.encodePacked(sig1, sig1);
        
        // Call verify (which internally calls verifyECDSA with sign_type=0)
        bool result = verifier.verify(msgHash, duplicatedSignatures, 0);
        
        // Property: With only 1 unique validator signing (even if signature is duplicated),
        // verification MUST fail when required_validators is 2
        // In fixed code: result should be false (PASS)
        // In vulnerable code: result is true (FAIL - this assert will fail)
        assert(!result);
    }
    
    /// @notice Additional check: verify that unique validators count is enforced
    /// Even with signature malleability creating different byte representations,
    /// the same signer should only count once
    function check_uniqueValidatorsRequired() public {
        bytes32 msgHash = keccak256("another test");
        
        // Sign with validator1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1PrivateKey, msgHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        
        // Only 1 validator registered, requiring 2
        // Single signature should fail
        bool resultSingle = verifier.verify(msgHash, sig, 0);
        
        // Duplicate signature (same signer twice) should also fail
        bytes memory duplicated = abi.encodePacked(sig, sig);
        bool resultDuplicated = verifier.verify(msgHash, duplicated, 0);
        
        // Both should fail - only 1 unique validator
        // In vulnerable code, resultDuplicated may be true (incorrectly)
        assert(!resultSingle);
        assert(!resultDuplicated);
    }
}
