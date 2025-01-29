// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title UUPSRecover
/// @dev A singleton contract meant to allow for generic recovery of ERC1967 proxies.
contract UUPSRecover is UUPSUpgradeable {
    error Unauthorized();

    struct Storage {
        address recoveryPublicKey;
    }

    // @dev Returns the storage pointer.
    function _getStorage() internal pure returns (Storage storage $) {
        // Truncate to 9 bytes to reduce bytecode size.
        uint256 s = uint72(bytes9(keccak256("UUPS_RECOVER_STORAGE")));
        assembly ("memory-safe") {
            $.slot := s
        }
    }

    function _setRecoveryPublicKey(address publicKey) internal {
        Storage storage $ = _getStorage();
        $.recoveryPublicKey = publicKey;
    }

    /// @dev Sets the recovery public key.
    /// @param publicKey The public key to set.
    /// @notice This function can only be called through a proxy.
    function setRecoveryPublicKey(address publicKey) public onlyProxy() {
        _setRecoveryPublicKey(publicKey);
    }

    modifier onlyRecovery() {
        Storage storage $ = _getStorage();
        if(msg.sender != $.recoveryPublicKey) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyRecoveryWithSignature(bytes32 digest, bytes memory signature) {
        Storage storage $ = _getStorage();
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(signature, (uint8, bytes32, bytes32));
        address signer = ecrecover(digest, v, r, s);
        if(signer != $.recoveryPublicKey || signer == address(0)) {
            revert Unauthorized();
        }
        _;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRecovery() {}

    function _authorizeUpgrade(address newImplementation, bytes32 digest, bytes memory signature) internal onlyRecoveryWithSignature(digest, signature) {}

    function upgradeToAndCall(address newImplementation, bytes memory data, bytes memory signature) public payable onlyProxy {
        bytes32 digest = keccak256(abi.encode(newImplementation, data));
        _authorizeUpgrade(newImplementation, digest, signature);
        // self delegateCall
        (bool success, ) = address(this).delegatecall(abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, newImplementation, data));
        if(!success) {
            revert("UUPSUpgradeable: upgrade failed");
        }
    }
}
