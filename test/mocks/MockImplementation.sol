// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {console} from "forge-std/console.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract MockImplementation is UUPSUpgradeable {
    error Unauthorized();

    /// @dev Only allows upgrades from the contract itself
    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(this)) {
            revert Unauthorized();
        }
    }

    /// @dev Version function to test successful upgrades
    function version() public pure returns (uint256) {
        return 1;
    }

    /// @dev Fallback function that delegate calls to the specified target, unsafe
    fallback() external {
        require(msg.sender == address(this), "Fallback not allowed");

        (address target, bytes memory data) = abi.decode(msg.data, (address, bytes));

        (bool success, bytes memory returndata) = target.delegatecall(data);

        // Handle the result
        if (success) {
            assembly {
                return(add(returndata, 32), mload(returndata))
            }
        } else {
            // Forward the revert reason
            assembly {
                revert(add(returndata, 32), mload(returndata))
            }
        }
    }

    // Allow receiving ETH
    receive() external payable {}
}
