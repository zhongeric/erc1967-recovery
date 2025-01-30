// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

/// @title UUPSRecover
/// @notice A singleton contract meant to allow for generic recovery of ERC1967 proxies.
/// @dev This contract should NOT be the target of a proxy, but rather should be delegate called by implementations.
///      the desired use case is to allow both the implementation and this contract to upgrade the proxy's ERC1967 slot.
contract UUPSRecover {
    error Unauthorized();
    error OnlyDelegated();
    error UpgradeFailed();
    /**
     * @dev The storage `slot` is unsupported as a UUID.
     */
    error UUPSUnsupportedProxiableUUID(bytes32 slot);

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

    /// @notice Only allow delegated calls
    modifier onlyDelegated() {
        if (msg.sender != address(this)) {
            revert OnlyDelegated();
        }
        _;
    }

    /// @notice Requires a valid signature from the registered recovery public key
    modifier onlyRecoveryWithSignature(bytes32 digest, bytes memory signature) {
        Storage storage $ = _getStorage();
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(signature, (uint8, bytes32, bytes32));
        address signer = ecrecover(digest, v, r, s);
        if (signer != $.recoveryPublicKey || signer == address(0)) {
            revert Unauthorized();
        }
        _;
    }

    /// @dev Sets the recovery public key.
    /// @param publicKey The public key to set.
    function setRecoveryPublicKey(address publicKey) public onlyDelegated {
        _setRecoveryPublicKey(publicKey);
    }

    function _authorizeUpgrade(address newImplementation, bytes32 digest, bytes memory signature)
        internal
        onlyRecoveryWithSignature(digest, signature)
    {}

    function upgradeToAndCall(address newImplementation, bytes memory data, bytes memory signature)
        public
        payable
        onlyDelegated
    {
        bytes32 digest = keccak256(abi.encode(newImplementation, data));
        _authorizeUpgrade(newImplementation, digest, signature);
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    /**
     * @dev Performs an implementation upgrade with a security check for UUPS proxies, and additional setup call.
     *
     * As a security check, {proxiableUUID} is invoked in the new implementation, and the return value
     * is expected to be the implementation slot in ERC-1967.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert UUPSUnsupportedProxiableUUID(slot);
            }
            ERC1967Utils.upgradeToAndCall(newImplementation, data);
        } catch {
            // The implementation is not UUPS
            revert ERC1967Utils.ERC1967InvalidImplementation(newImplementation);
        }
    }
}
