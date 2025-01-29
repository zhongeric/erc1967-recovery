// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {UUPSRecover} from "../src/UUPSRecover.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract UUPSRecoverTest is Test {
    UUPSRecover public implementation;
    UUPSRecover public proxy;
    address public recoveryKey;
    uint256 public recoveryPrivateKey;

    event Upgraded(address indexed implementation);

    function setUp() public {
        // Deploy implementation
        implementation = new UUPSRecover();
        
        // Create proxy
        bytes memory initData = "";
        ERC1967Proxy proxyContract = new ERC1967Proxy(address(implementation), initData);
        proxy = UUPSRecover(address(proxyContract));

        // Setup recovery key
        (recoveryKey, recoveryPrivateKey) = makeAddrAndKey("recovery");
        proxy.setRecoveryPublicKey(recoveryKey);
    }

    function test_SetRecoveryKey() public {
        address newKey = makeAddr("newKey");
        proxy.setRecoveryPublicKey(newKey);
        
        // Access storage directly using the same slot derivation
        bytes32 slot = bytes32(uint256(uint72(bytes9(keccak256("UUPS_RECOVER_STORAGE")))));
        address storedKey = address(uint160(uint256(vm.load(address(proxy), slot))));
        
        assertEq(storedKey, newKey, "Recovery key not properly set");
    }

    function test_OnlyProxyCanSetRecoveryKey() public {
        vm.expectRevert("Function must be called through delegatecall");
        implementation.setRecoveryPublicKey(address(0));
    }

    function test_UpgradeWithRecoveryKey() public {
        // Deploy new implementation
        UUPSRecover newImplementation = new UUPSRecover();
        
        // Upgrade using recovery key
        vm.prank(recoveryKey);
        proxy.upgradeTo(address(newImplementation));
        
        assertEq(ERC1967Proxy(payable(address(proxy))).implementation(), address(newImplementation));
    }

    function test_UpgradeWithSignature() public {
        // Deploy new implementation
        UUPSRecover newImplementation = new UUPSRecover();
        
        bytes memory data = "";
        bytes32 digest = keccak256(abi.encode(address(newImplementation), data));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(recoveryPrivateKey, digest);
        bytes memory signature = abi.encode(v, r, s);
        
        proxy.upgradeToAndCall(address(newImplementation), data, signature);
        
        assertEq(ERC1967Proxy(payable(address(proxy))).implementation(), address(newImplementation));
    }

    function test_RevertUnauthorizedUpgrade() public {
        UUPSRecover newImplementation = new UUPSRecover();
        
        vm.expectRevert(UUPSRecover.Unauthorized.selector);
        proxy.upgradeTo(address(newImplementation));
    }

    function test_RevertInvalidSignature() public {
        UUPSRecover newImplementation = new UUPSRecover();
        bytes memory data = "";
        bytes32 digest = keccak256(abi.encode(address(newImplementation), data));
        
        // Sign with wrong key
        (uint256 wrongKey,) = makeAddrAndKey("wrong");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory signature = abi.encode(v, r, s);
        
        vm.expectRevert(UUPSRecover.Unauthorized.selector);
        proxy.upgradeToAndCall(address(newImplementation), data, signature);
    }

    function test_RevertZeroAddressSignature() public {
        UUPSRecover newImplementation = new UUPSRecover();
        bytes memory data = "";
        bytes32 digest = keccak256(abi.encode(address(newImplementation), data));
        
        // Create signature that would recover to address(0)
        bytes memory signature = abi.encode(uint8(27), bytes32(0), bytes32(0));
        
        vm.expectRevert(UUPSRecover.Unauthorized.selector);
        proxy.upgradeToAndCall(address(newImplementation), data, signature);
    }
} 