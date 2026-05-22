// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {CDPVault} from "src/CDPVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev Minimal mock for IOracle
contract MockOracle {
    function spot(address) external pure returns (uint256) {
        return 1e18;
    }
}

/// @dev Minimal mock for IERC20
contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public decimals = 18;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

/// @dev Minimal mock for IPoolV3
contract MockPool {
    address public underlying;
    address public quotaKeeper;
    uint256 public baseInterestIndex = 1e27;

    constructor(address _underlying, address _quotaKeeper) {
        underlying = _underlying;
        quotaKeeper = _quotaKeeper;
    }

    function poolQuotaKeeper() external view returns (address) {
        return quotaKeeper;
    }

    function baseInterestRate() external pure returns (uint256) {
        return 0;
    }

    function baseInterestIndexLU() external view returns (uint256) {
        return baseInterestIndex;
    }

    function lendCreditAccount(uint256, address) external {}
    function repayCreditAccount(uint256, uint256, uint256) external {}
    function mintProfit(uint256) external {}
    function enter(address, uint256) external {}
    function exit(address, uint256) external {}
    function addAvailable(address, int256) external {}
}

/// @dev Minimal mock for IPoolQuotaKeeperV3
contract MockQuotaKeeper {
    function getQuotaRate(address) external pure returns (uint16) {
        return 0;
    }

    function cumulativeIndex(address) external pure returns (uint192) {
        return 1e27;
    }

    function updateQuota(address, int96, uint96) external pure returns (uint128, uint128, bool) {
        return (0, 0, false);
    }
}

contract Test2024_07_loopfi_due_to_missing_whennotpaused_modifiers_o is Test, SymTest {
    CDPVault vault;
    MockToken token;
    MockToken poolUnderlying;
    MockOracle oracle;
    MockPool pool;
    MockQuotaKeeper quotaKeeper;
    
    address admin;
    address pauser;
    address borrower;

    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        admin = address(this);
        pauser = makeAddr("pauser");
        borrower = makeAddr("borrower");

        token = new MockToken();
        poolUnderlying = new MockToken();
        oracle = new MockOracle();
        quotaKeeper = new MockQuotaKeeper();
        pool = new MockPool(address(poolUnderlying), address(quotaKeeper));

        // Deploy the real CDPVault
        vault = new CDPVault(
            CDPVault.CDPVaultParams({
                pool: address(pool),
                oracle: address(oracle),
                token: address(token),
                tokenScale: 1e18
            }),
            CDPVault.CDPVaultConfigs({
                debtFloor: 0,
                liquidationRatio: 1.5e18,
                liquidationPenalty: 1e18,
                liquidationDiscount: 0.95e18
            })
        );

        // Grant PAUSER_ROLE to pauser address
        vault.grantRole(PAUSER_ROLE, pauser);

        // Setup borrower with some collateral
        token.mint(borrower, 1000e18);
        vm.prank(borrower);
        token.approve(address(vault), type(uint256).max);
    }

    /// @notice Checks that borrow MUST revert when the contract is paused
    /// @dev On FIXED code (with whenNotPaused modifier), this should PASS (borrow reverts when paused)
    /// @dev On VULNERABLE code (missing whenNotPaused modifier), this should FAIL (borrow succeeds when paused)
    function check_borrow_reverts_when_paused() public {
        // Setup: pause the contract
        vm.prank(pauser);
        vault.pause();

        // Precondition: verify contract is paused
        assert(vault.paused());

        // Action: attempt to borrow when paused
        vm.prank(borrower);
        (bool success, ) = address(vault).call(
            abi.encodeWithSelector(
                CDPVault.borrow.selector,
                borrower,  // receiver
                borrower,  // position owner
                1e18       // amount to borrow
            )
        );

        // Invariant: borrow MUST revert when contract is paused
        // If success is true, the invariant is violated (vulnerable code)
        // If success is false, the invariant holds (fixed code)
        assert(!success);
    }
}
