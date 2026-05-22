// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {LlamaRelativeQuorum} from "src/strategies/LlamaRelativeQuorum.sol";

/// @dev Minimal stub for LlamaCore dependency
contract MockLlamaCore {
    function getAction(uint256) external pure returns (
        uint128 totalApprovals,
        uint128 totalDisapprovals,
        uint64 creationTime,
        uint64 minExecutionTime,
        bool executed,
        bool canceled
    ) {
        return (0, 0, 0, 0, false, false);
    }
    
    function getActionState(bytes calldata) external pure returns (uint8) {
        return 0;
    }
}

/// @dev Minimal stub for LlamaPolicy dependency
contract MockLlamaPolicy {
    uint8 public numRoles = 10;
    
    function getRoleSupplyAsNumberOfHolders(uint8) external pure returns (uint128) {
        return 100;
    }
    
    function getRoleSupplyAsQuantitySum(uint8) external pure returns (uint128) {
        return 1000;
    }
    
    function getPastQuantity(address, uint8, uint256) external pure returns (uint128) {
        return 10;
    }
}

contract Test2023_06_llama_H_02 is Test, SymTest {
    LlamaRelativeQuorum strategy;
    address llamaCore;
    address llamaPolicy;
    
    // ActionInfo struct matching the contract's expected structure
    struct ActionInfo {
        uint256 id;
        address creator;
        uint8 creatorRole;
        address strategy;
        address target;
        uint256 value;
        bytes data;
    }

    function setUp() public {
        // Deploy mock dependencies
        MockLlamaCore mockCore = new MockLlamaCore();
        MockLlamaPolicy mockPolicy = new MockLlamaPolicy();
        
        llamaCore = address(mockCore);
        llamaPolicy = address(mockPolicy);
        
        // Deploy the real LlamaRelativeQuorum strategy
        strategy = new LlamaRelativeQuorum();
        
        // Initialize the strategy - it expects to be called by a LlamaCore
        // The initialization sets llamaCore to msg.sender
        uint8[] memory forceApprovalRoles = new uint8[](0);
        uint8[] memory forceDisapprovalRoles = new uint8[](0);
        
        // Config struct encoded for initialization
        bytes memory config = abi.encode(
            uint64(1 days),    // approvalPeriod
            uint64(1 days),    // queuingPeriod  
            uint64(1 days),    // expirationPeriod
            uint16(5000),      // minApprovalPct (50%)
            uint16(5000),      // minDisapprovalPct (50%)
            false,             // isFixedLengthApprovalPeriod
            uint8(1),          // approvalRole
            uint8(2),          // disapprovalRole
            forceApprovalRoles,
            forceDisapprovalRoles
        );
        
        // Initialize from llamaCore address so llamaCore is set correctly
        vm.prank(llamaCore);
        strategy.initialize(config);
    }

    /// @notice Property: validateActionCreation MUST revert when caller is not LlamaCore
    /// @dev In the vulnerable version, anyone can call validateActionCreation and manipulate
    ///      actionApprovalSupply and actionDisapprovalSupply mappings
    function check_validateActionCreation_onlyLlamaCore() public {
        // Create a symbolic caller address
        address caller = svm.createAddress("caller");
        
        // Assume caller is NOT the llamaCore contract
        vm.assume(caller != llamaCore);
        vm.assume(caller != address(0));
        
        // Construct ActionInfo for the call
        ActionInfo memory actionInfo = ActionInfo({
            id: 1,
            creator: address(0x1234),
            creatorRole: 1,
            strategy: address(strategy),
            target: address(0x5678),
            value: 0,
            data: ""
        });
        
        // Prank as the non-llamaCore caller
        vm.prank(caller);
        
        // Try to call validateActionCreation
        // In fixed code: should revert because caller != llamaCore
        // In vulnerable code: succeeds, allowing manipulation of approval/disapproval supply
        (bool success,) = address(strategy).call(
            abi.encodeWithSignature(
                "validateActionCreation((uint256,address,uint8,address,address,uint256,bytes))",
                actionInfo
            )
        );
        
        // Assert that the call must fail (revert) when caller is not llamaCore
        // This assertion should PASS on fixed code (call reverts, success=false)
        // This assertion should FAIL on vulnerable code (call succeeds, success=true)
        assert(!success);
    }
}
