// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {SettlementSignatureVerifier} from "solidity/settlement/contracts/SettlementSignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Test2024_08_chakra_default_admin_role_not_revoked_on_owners is Test, SymTest {
    SettlementSignatureVerifier verifier;
    address oldOwner;
    address newOwner;

    function setUp() public {
        oldOwner = address(0x1111);
        newOwner = address(0x2222);

        // Deploy implementation
        SettlementSignatureVerifier impl = new SettlementSignatureVerifier();

        // Deploy proxy and initialize
        bytes memory initData = abi.encodeWithSelector(
            SettlementSignatureVerifier.initialize.selector,
            oldOwner,
            1
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        verifier = SettlementSignatureVerifier(address(proxy));
    }

    /// @notice After transferOwnership, the old owner should no longer have DEFAULT_ADMIN_ROLE
    /// @dev This property should PASS on fixed code (old owner loses admin role)
    ///      and FAIL on vulnerable code (old owner retains admin role)
    function check_transferOwnership_revokes_admin_role() public {
        // Verify initial state: oldOwner has DEFAULT_ADMIN_ROLE
        bytes32 defaultAdminRole = verifier.DEFAULT_ADMIN_ROLE();
        assert(verifier.hasRole(defaultAdminRole, oldOwner));
        assert(verifier.owner() == oldOwner);

        // Transfer ownership from oldOwner to newOwner
        vm.prank(oldOwner);
        verifier.transferOwnership(newOwner);

        // Accept ownership (OwnableUpgradeable uses two-step transfer in newer versions)
        // For older versions, ownership is transferred immediately
        // Check the actual owner after transfer
        address currentOwner = verifier.owner();

        // If two-step transfer is used, newOwner needs to accept
        if (currentOwner == oldOwner) {
            // Two-step transfer: newOwner must accept
            vm.prank(newOwner);
            verifier.acceptOwnership();
        }

        // After ownership transfer completes, old owner should NOT have DEFAULT_ADMIN_ROLE
        // This is the invariant that is violated in the vulnerable code
        bool oldOwnerStillHasAdminRole = verifier.hasRole(defaultAdminRole, oldOwner);

        // The property: old owner should NOT retain admin role after ownership transfer
        // On FIXED code: oldOwnerStillHasAdminRole == false, so assertion passes
        // On VULNERABLE code: oldOwnerStillHasAdminRole == true, so assertion fails
        assert(!oldOwnerStillHasAdminRole);
    }
}
