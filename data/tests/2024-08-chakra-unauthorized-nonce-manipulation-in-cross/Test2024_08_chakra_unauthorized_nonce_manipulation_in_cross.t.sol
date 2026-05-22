// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {ChakraSettlement} from "solidity/settlement/contracts/ChakraSettlement.sol";
import {PayloadType} from "solidity/settlement/contracts/libraries/Message.sol";

contract MockSignatureVerifier {
    function verify(bytes32, bytes calldata, uint8) external pure returns (bool) {
        return true;
    }
}

contract Test2024_08_chakra_unauthorized_nonce_manipulation_in_cross is Test, SymTest {
    ChakraSettlement settlement;
    address owner;
    address manager;
    address unauthorizedCaller;
    bytes32 public constant HANDLER_ROLE = keccak256("HANDLER_ROLE");

    function setUp() public {
        owner = address(0x1001);
        manager = address(0x1002);
        unauthorizedCaller = address(0x1003);

        MockSignatureVerifier verifier = new MockSignatureVerifier();

        settlement = new ChakraSettlement();

        address[] memory managers = new address[](1);
        managers[0] = manager;

        settlement.initialize(
            "TestChain",
            1,
            owner,
            managers,
            1,
            address(verifier)
        );
    }

    function check_send_cross_chain_msg_access_control() public {
        address caller = svm.createAddress("caller");
        address fromAddress = svm.createAddress("fromAddress");

        bool hasHandlerRole = settlement.hasRole(HANDLER_ROLE, caller);
        vm.assume(!hasHandlerRole);

        uint256 nonceBefore = settlement.nonce_manager(fromAddress);

        bytes memory payload = hex"1234";

        vm.prank(caller);
        (bool success, ) = address(settlement).call(
            abi.encodeWithSelector(
                settlement.send_cross_chain_msg.selector,
                "DestChain",
                fromAddress,
                uint256(0x2000),
                PayloadType.ERC20,
                payload
            )
        );

        uint256 nonceAfter = settlement.nonce_manager(fromAddress);

        assert(!success || hasHandlerRole);

        assert(nonceAfter == nonceBefore || hasHandlerRole);
    }
}
