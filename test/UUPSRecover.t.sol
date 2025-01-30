// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {UUPSRecover} from "../src/UUPSRecover.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockImplementation} from "./mocks/MockImplementation.sol";
import {Mock1967Proxy, IMock1967Proxy} from "./mocks/Mock1967Proxy.sol";

contract UUPSRecoverTest is Test {
    UUPSRecover public recover;
    MockImplementation public implementation;
    Mock1967Proxy public proxy;
    address public recoveryKey;
    uint256 public recoveryPrivateKey;

    error UUPSUnauthorizedCallContext();

    event Upgraded(address indexed implementation);

    uint256 alicePrivateKey = 0x1234;
    address payable ALICE = payable(vm.addr(alicePrivateKey));

    function prankAndSelfCall(bytes memory data) internal returns (bool success, bytes memory returnData) {
        vm.prank(ALICE);
        (success, returnData) = ALICE.call(data);
    }

    function setUp() public {
        // Deploy implementation
        implementation = new MockImplementation();
        vm.label(address(implementation), "IMPLEMENTATION");
        // Create proxy
        bytes memory initData = "";
        proxy = new Mock1967Proxy(address(implementation), initData);
        vm.label(address(proxy), "PROXY");

        vm.label(ALICE, "ALICE");
        // Write the delegation designation to alice's EOA
        vm.etch(ALICE, bytes.concat(hex"ef0100", abi.encodePacked(proxy)));
        require(ALICE.code.length > 0, "ALICE must have code");

        IMock1967Proxy(ALICE).upgradeToAndCall(address(implementation), "");

        // Deploy recover
        recover = new UUPSRecover();
        vm.label(address(recover), "RECOVER");

        assertEq(
            IMock1967Proxy(ALICE).implementation(), address(implementation), "Proxy implementation not properly set"
        );

        // Setup recovery key
        (recoveryKey, recoveryPrivateKey) = makeAddrAndKey("recovery");
        // Set recovery key
        bytes memory data =
            abi.encode(address(recover), abi.encodeWithSelector(UUPSRecover.setRecoveryPublicKey.selector, recoveryKey));
        (bool success,) = prankAndSelfCall(data);
        assertTrue(success, "Failed to set recovery key");
    }

    function test_NormalUpgrade() public {
        // Deploy new implementation
        UUPSRecover newImplementation = new UUPSRecover();
        IMock1967Proxy(ALICE).upgradeToAndCall(address(newImplementation), "");

        // read implementation slot
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address storedKey = address(uint160(uint256(vm.load(address(ALICE), slot))));
        assertEq(storedKey, address(newImplementation), "Implementation not properly set");
    }

    function test_SetRecoveryKey() public {
        address newKey = makeAddr("newKey");
        bytes memory data =
            abi.encode(address(recover), abi.encodeWithSelector(UUPSRecover.setRecoveryPublicKey.selector, newKey));
        (bool success,) = prankAndSelfCall(data);
        assertTrue(success, "Failed to set recovery key");

        // Access storage directly using the same slot derivation
        bytes32 slot = bytes32(uint256(uint72(bytes9(keccak256("UUPS_RECOVER_STORAGE")))));
        address storedKey = address(uint160(uint256(vm.load(ALICE, slot))));
        assertEq(storedKey, newKey, "Recovery key not properly set");
    }

    function test_OnlyProxyCanSetRecoveryKey() public {
        vm.expectRevert(UUPSUnauthorizedCallContext.selector);
        bytes memory data = abi.encodeWithSelector(UUPSRecover.setRecoveryPublicKey.selector, address(0));
        (bool success,) = prankAndSelfCall(data);
        assertTrue(!success, "Expected revert");
    }

    function test_UpgradeWithSignature() public {
        // Deploy new implementation
        UUPSRecover newImplementation = new UUPSRecover();

        bytes memory data = "";
        bytes32 digest = keccak256(abi.encode(address(newImplementation), data));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(recoveryPrivateKey, digest);
        bytes memory signature = abi.encode(v, r, s);

        bytes memory callData = abi.encode(
            address(recover),
            abi.encodeWithSignature(
                "upgradeToAndCall(address,bytes,bytes)", address(newImplementation), data, signature
            )
        );
        (bool success,) = prankAndSelfCall(callData);
        assertTrue(success, "Failed to upgrade");

        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address storedKey = address(uint160(uint256(vm.load(address(ALICE), slot))));
        assertEq(storedKey, address(newImplementation), "Implementation not properly set");
    }

    function test_RevertInvalidSignature() public {
        UUPSRecover newImplementation = new UUPSRecover();
        bytes memory data = "";
        bytes32 digest = keccak256(abi.encode(address(newImplementation), data));

        // Sign with wrong key
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory signature = abi.encode(v, r, s);

        bytes memory callData = abi.encode(
            address(recover),
            abi.encodeWithSignature(
                "upgradeToAndCall(address,bytes,bytes)", address(newImplementation), data, signature
            )
        );
        vm.expectRevert(UUPSRecover.Unauthorized.selector);
        prankAndSelfCall(callData);
    }

    function test_RevertZeroAddressSignature() public {
        UUPSRecover newImplementation = new UUPSRecover();
        bytes memory data = "";

        // Create signature that would recover to address(0)
        bytes memory signature = abi.encode(uint8(27), bytes32(0), bytes32(0));

        bytes memory callData = abi.encode(
            address(recover),
            abi.encodeWithSignature(
                "upgradeToAndCall(address,bytes,bytes)", address(newImplementation), data, signature
            )
        );
        vm.expectRevert(UUPSRecover.Unauthorized.selector);
        prankAndSelfCall(callData);
    }
}
