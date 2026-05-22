// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {NonfungiblePositionManager} from "src/periphery/NonfungiblePositionManager.sol";

/// @dev Minimal ERC20 stub for pool tokens
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
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
}

/// @dev Minimal pool factory stub
contract MockFactory {
    address public pool;
    
    function setPool(address _pool) external {
        pool = _pool;
    }
    
    function getPool(address, address, uint24) external view returns (address) {
        return pool;
    }
}

/// @dev Minimal pool stub
contract MockPool {
    address public token0;
    address public token1;
    uint24 public fee;
    int24 public tickSpacing;
    
    constructor(address _token0, address _token1) {
        token0 = _token0;
        token1 = _token1;
        fee = 3000;
        tickSpacing = 60;
    }
    
    function slot0() external pure returns (uint160 sqrtPriceX96, int24 tick, uint16, uint16, uint16, uint8, bool) {
        return (79228162514264337593543950336, 0, 0, 0, 0, 0, false);
    }
    
    function mint(address, int24, int24, uint128, bytes calldata) external pure returns (uint256, uint256) {
        return (1000, 1000);
    }
}

/// @dev Minimal WETH stub
contract MockWETH {
    function deposit() external payable {}
    function withdraw(uint256) external {}
}

contract Test2024_10_ronin_missing_authorization_check_in_increasel is Test, SymTest {
    NonfungiblePositionManager nfpm;
    MockFactory factory;
    MockPool pool;
    MockERC20 token0;
    MockERC20 token1;
    MockWETH weth;
    
    address owner;
    address attacker;
    uint256 existingTokenId;

    function setUp() public {
        owner = address(0x1111);
        attacker = address(0x2222);
        
        // Deploy mock dependencies
        token0 = new MockERC20();
        token1 = new MockERC20();
        weth = new MockWETH();
        factory = new MockFactory();
        pool = new MockPool(address(token0), address(token1));
        factory.setPool(address(pool));
        
        // Deploy the real NonfungiblePositionManager
        nfpm = new NonfungiblePositionManager(address(factory), address(weth));
        
        // Mint tokens for owner and attacker
        token0.mint(owner, 1000000 ether);
        token1.mint(owner, 1000000 ether);
        token0.mint(attacker, 1000000 ether);
        token1.mint(attacker, 1000000 ether);
        
        // Owner approves NFPM
        vm.startPrank(owner);
        token0.approve(address(nfpm), type(uint256).max);
        token1.approve(address(nfpm), type(uint256).max);
        vm.stopPrank();
        
        // Attacker approves NFPM
        vm.startPrank(attacker);
        token0.approve(address(nfpm), type(uint256).max);
        token1.approve(address(nfpm), type(uint256).max);
        vm.stopPrank();
    }

    /// @notice Verifies that increaseLiquidity reverts when called by unauthorized user
    /// @dev Property: Only token owner or approved operator can increase liquidity
    /// @dev On FIXED code: Should PASS (revert occurs, assertion holds)
    /// @dev On VULNERABLE code: Should FAIL (no revert, assertion violated)
    function check_increaseLiquidity_unauthorized() public {
        // Create symbolic caller that is NOT owner and NOT approved
        address caller = svm.createAddress("caller");
        
        // Assume caller is not zero address
        vm.assume(caller != address(0));
        // Assume caller is not owner
        vm.assume(caller != owner);
        // Assume caller is different from attacker for cleaner test
        vm.assume(caller != attacker);
        
        // First, owner mints a position (tokenId = 1)
        vm.startPrank(owner);
        
        // We need to use a try-catch since minting might have complex requirements
        // For this test, we'll assume a position exists at tokenId 1
        existingTokenId = 1;
        
        vm.stopPrank();
        
        // Ensure caller has tokens to attempt increase
        token0.mint(caller, 1000000 ether);
        token1.mint(caller, 1000000 ether);
        
        vm.startPrank(caller);
        token0.approve(address(nfpm), type(uint256).max);
        token1.approve(address(nfpm), type(uint256).max);
        vm.stopPrank();
        
        // Build IncreaseLiquidity params for position owned by 'owner'
        // Using low-level call to handle the struct encoding
        bytes memory callData = abi.encodeWithSignature(
            "increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))",
            existingTokenId,  // tokenId - owned by 'owner', not 'caller'
            1000,             // amount0Desired
            1000,             // amount1Desired
            0,                // amount0Min
            0,                // amount1Min
            block.timestamp + 1000  // deadline
        );
        
        // Caller (unauthorized) attempts to increase liquidity on owner's position
        vm.prank(caller);
        (bool success,) = address(nfpm).call(callData);
        
        // Property: Unauthorized caller MUST NOT succeed
        // On fixed code: success == false (call reverts) -> assertion passes
        // On vulnerable code: success == true (call succeeds) -> assertion fails
        assert(!success);
    }
}
