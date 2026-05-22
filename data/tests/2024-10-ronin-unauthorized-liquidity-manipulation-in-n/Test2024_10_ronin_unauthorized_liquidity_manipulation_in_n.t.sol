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

/// @dev Minimal factory stub
contract MockFactory {
    address public poolAddress;
    
    function setPool(address _pool) external {
        poolAddress = _pool;
    }
    
    function getPool(address, address, uint24) external view returns (address) {
        return poolAddress;
    }
}

/// @dev Minimal pool stub
contract MockPool {
    address public token0;
    address public token1;
    uint24 public fee;
    int24 public tickSpacing;
    
    constructor(address _token0, address _token1, uint24 _fee) {
        token0 = _token0;
        token1 = _token1;
        fee = _fee;
        tickSpacing = 60;
    }
    
    function slot0() external pure returns (uint160, int24, uint16, uint16, uint16, uint8, bool) {
        return (79228162514264337593543950336, 0, 0, 0, 0, 0, false);
    }
    
    function positions(bytes32) external pure returns (uint128, uint256, uint256, uint128, uint128) {
        return (1000, 0, 0, 0, 0);
    }
    
    function mint(address, int24, int24, uint128, bytes calldata) external returns (uint256, uint256) {
        return (100, 100);
    }
}

/// @dev Minimal WETH stub
contract MockWETH {
    function deposit() external payable {}
    function withdraw(uint256) external {}
    function transfer(address, uint256) external returns (bool) { return true; }
}

contract Test2024_10_ronin_unauthorized_liquidity_manipulation_in_n is Test, SymTest {
    NonfungiblePositionManager npm;
    MockFactory factory;
    MockPool pool;
    MockERC20 token0;
    MockERC20 token1;
    MockWETH weth;
    
    address owner;
    address unauthorized;
    uint256 existingTokenId;

    function setUp() public {
        owner = makeAddr("owner");
        unauthorized = makeAddr("unauthorized");
        
        // Deploy mocks
        token0 = new MockERC20();
        token1 = new MockERC20();
        factory = new MockFactory();
        weth = new MockWETH();
        pool = new MockPool(address(token0), address(token1), 3000);
        factory.setPool(address(pool));
        
        // Deploy NonfungiblePositionManager
        npm = new NonfungiblePositionManager(address(factory), address(weth));
        
        // Mint tokens to owner for creating position
        token0.mint(owner, 1e24);
        token1.mint(owner, 1e24);
        
        // Owner creates a position (mints NFT)
        vm.startPrank(owner);
        token0.approve(address(npm), type(uint256).max);
        token1.approve(address(npm), type(uint256).max);
        
        // Create mint params
        NonfungiblePositionManager.MintParams memory mintParams = NonfungiblePositionManager.MintParams({
            token0: address(token0),
            token1: address(token1),
            fee: 3000,
            tickLower: -60,
            tickUpper: 60,
            amount0Desired: 1000,
            amount1Desired: 1000,
            amount0Min: 0,
            amount1Min: 0,
            recipient: owner,
            deadline: block.timestamp + 1000
        });
        
        (existingTokenId,,,) = npm.mint(mintParams);
        vm.stopPrank();
        
        // Give unauthorized user tokens
        token0.mint(unauthorized, 1e24);
        token1.mint(unauthorized, 1e24);
        
        vm.startPrank(unauthorized);
        token0.approve(address(npm), type(uint256).max);
        token1.approve(address(npm), type(uint256).max);
        vm.stopPrank();
    }

    /// @notice Verifies that unauthorized users cannot increase liquidity on positions they don't own
    /// @dev On FIXED code: unauthorized call reverts (assertion passes)
    /// @dev On VULNERABLE code: unauthorized call succeeds (assertion fails)
    function check_increaseLiquidity_unauthorized() public {
        // Verify preconditions: unauthorized is not owner and has no approval
        address tokenOwner = npm.ownerOf(existingTokenId);
        assert(tokenOwner == owner);
        assert(unauthorized != owner);
        assert(npm.getApproved(existingTokenId) != unauthorized);
        assert(!npm.isApprovedForAll(owner, unauthorized));
        
        // Prepare increase liquidity params
        NonfungiblePositionManager.IncreaseLiquidityParams memory params = NonfungiblePositionManager.IncreaseLiquidityParams({
            tokenId: existingTokenId,
            amount0Desired: 100,
            amount1Desired: 100,
            amount0Min: 0,
            amount1Min: 0,
            deadline: block.timestamp + 1000
        });
        
        // Unauthorized user attempts to increase liquidity
        vm.prank(unauthorized);
        (bool success,) = address(npm).call(
            abi.encodeWithSelector(NonfungiblePositionManager.increaseLiquidity.selector, params)
        );
        
        // Property: unauthorized calls MUST revert (success should be false)
        // On FIXED code: success == false, assertion passes
        // On VULNERABLE code: success == true, assertion fails
        assert(!success);
    }
}
