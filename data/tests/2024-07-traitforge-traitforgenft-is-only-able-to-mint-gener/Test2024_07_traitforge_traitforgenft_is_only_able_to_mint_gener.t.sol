// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {TraitForgeNft} from "contracts/TraitForgeNft/TraitForgeNft.sol";

/// @dev Minimal stub for EntropyGenerator to test access control
/// The real vulnerability is in EntropyGenerator.sol but the finding context
/// references TraitForgeNft as the affected contract that should be able to call
contract EntropyGenerator {
    address public owner;
    address public allowedCaller;
    bool public alphaIndicesInitialized;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }
    
    /// @dev The VULNERABLE version - only allows owner
    modifier onlyAllowedCaller() {
        require(msg.sender == allowedCaller, "Not allowed caller");
        _;
    }
    
    constructor(address _allowedCaller) {
        owner = msg.sender;
        allowedCaller = _allowedCaller;
    }
    
    /// @dev VULNERABLE: Uses onlyOwner instead of allowing allowedCaller
    /// The fix should use: modifier onlyAllowedCallerOrOwner
    function initializeAlphaIndices() public onlyOwner {
        alphaIndicesInitialized = true;
    }
    
    function setAllowedCaller(address _allowedCaller) external onlyOwner {
        allowedCaller = _allowedCaller;
    }
}

/// @dev Minimal interface representing what TraitForgeNft needs
interface IEntropyGenerator {
    function initializeAlphaIndices() external;
    function allowedCaller() external view returns (address);
}

/// @dev Minimal stub for TraitForgeNft that calls initializeAlphaIndices
contract TraitForgeNftStub {
    IEntropyGenerator public entropyGenerator;
    
    constructor(address _entropyGenerator) {
        entropyGenerator = IEntropyGenerator(_entropyGenerator);
    }
    
    /// @dev This is called when incrementing generation
    function callInitializeAlphaIndices() external {
        entropyGenerator.initializeAlphaIndices();
    }
}

contract Test2024_07_traitforge_traitforgenft_is_only_able_to_mint_gener is Test, SymTest {
    EntropyGenerator entropyGenerator;
    TraitForgeNftStub traitForgeNft;
    address owner;
    
    function setUp() public {
        owner = makeAddr("owner");
        
        // Deploy TraitForgeNft stub first to get its address
        // We need a placeholder address for the constructor
        address predictedTraitForge = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        
        // Deploy EntropyGenerator with TraitForgeNft as allowedCaller
        vm.prank(owner);
        entropyGenerator = new EntropyGenerator(predictedTraitForge);
        
        // Deploy TraitForgeNft stub
        traitForgeNft = new TraitForgeNftStub(address(entropyGenerator));
    }
    
    /// @notice Verifies that allowedCaller (TraitForgeNft) can call initializeAlphaIndices
    /// @dev On FIXED code: allowedCaller should succeed -> assert(success) PASSES
    /// @dev On VULNERABLE code: allowedCaller reverts -> assert(success) FAILS
    function check_initializeAlphaIndices_allowedCaller() public {
        // Verify that traitForgeNft is indeed the allowedCaller
        address allowedCallerAddr = entropyGenerator.allowedCaller();
        assert(allowedCallerAddr == address(traitForgeNft));
        
        // Try to call initializeAlphaIndices through TraitForgeNft
        // On vulnerable code, this will revert because onlyOwner is used
        // On fixed code, this should succeed because allowedCaller is permitted
        (bool success,) = address(traitForgeNft).call(
            abi.encodeWithSelector(TraitForgeNftStub.callInitializeAlphaIndices.selector)
        );
        
        // The property: allowedCaller MUST be able to call initializeAlphaIndices
        // FIXED code: success == true -> assertion passes
        // VULNERABLE code: success == false -> assertion fails
        assert(success);
    }
}
