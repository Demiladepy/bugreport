// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {WellUpgradeable} from "src/WellUpgradeable.sol";
import {WellDeployer} from "script/helpers/WellDeployer.sol";
import {Well, Call, IWellFunction, IPump, IERC20} from "src/Well.sol";
import {ConstantProduct2} from "src/functions/ConstantProduct2.sol";
import {Aquifer} from "src/Aquifer.sol";
import {LibWellUpgradeableConstructor} from "src/libraries/LibWellUpgradeableConstructor.sol";
import {MockToken} from "mocks/tokens/MockToken.sol";
import {MockPump} from "mocks/pumps/MockPump.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";
import {MockWellUpgradeable} from "mocks/wells/MockWellUpgradeable.sol";

/// @notice Halmos test: non-owner upgradeTo MUST revert on WellUpgradeable proxy.
contract Test2024_07_basin_H_01 is Test, SymTest, WellDeployer {
    address proxyAddress;
    address aquifer;
    address initialOwner;
    address attacker;
    address newWellProxy;

    function setUp() public {
        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = new MockToken("BEAN", "BEAN", 6);
        tokens[1] = new MockToken("WETH", "WETH", 18);

        IWellFunction cp2 = new ConstantProduct2();
        Call memory wellFunction = Call(address(cp2), abi.encode("beanstalkFunction"));

        IPump mockPump = new MockPump();
        Call[] memory pumps = new Call[](1);
        pumps[0] = Call(address(mockPump), abi.encode("beanstalkPump"));

        aquifer = address(new Aquifer());
        address wellImplementation = address(new WellUpgradeable());
        initialOwner = makeAddr("owner");

        WellUpgradeable well = encodeAndBoreWellUpgradeable(
            aquifer, wellImplementation, tokens, wellFunction, pumps, bytes32(0)
        );

        vm.startPrank(initialOwner);
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(well),
            LibWellUpgradeableConstructor.encodeWellInitFunctionCall(tokens, wellFunction)
        );
        vm.stopPrank();
        proxyAddress = address(proxy);

        IERC20[] memory upgradeTokens = new IERC20[](2);
        upgradeTokens[0] = new MockToken("BEAN2", "BEAN2", 6);
        upgradeTokens[1] = new MockToken("WETH2", "WETH2", 18);
        Call memory upgradeWellFunction = Call(address(cp2), abi.encode("2"));
        Call[] memory upgradePumps = new Call[](1);
        upgradePumps[0] = Call(address(mockPump), abi.encode("2"));
        address upgradeWellImpl = address(new MockWellUpgradeable());
        WellUpgradeable upgradeWell = encodeAndBoreWellUpgradeable(
            aquifer, upgradeWellImpl, upgradeTokens, upgradeWellFunction, upgradePumps, bytes32(abi.encode("2"))
        );
        newWellProxy = address(upgradeWell);

        attacker = svm.createAddress("attacker");
        vm.assume(attacker != initialOwner);
        vm.assume(attacker != address(0));
    }

    /// @dev FAIL on vulnerable commit (non-owner upgrade succeeds).
    /// @dev PASS on fixed commit (non-owner upgrade reverts).
    function check_upgradeToOnlyOwner() public {
        vm.assume(attacker != WellUpgradeable(proxyAddress).owner());

        vm.prank(attacker);
        (bool success,) = proxyAddress.call(
            abi.encodeWithSelector(WellUpgradeable.upgradeTo.selector, newWellProxy)
        );

        assert(!success);
    }
}
