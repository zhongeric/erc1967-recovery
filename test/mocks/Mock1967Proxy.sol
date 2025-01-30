// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

interface IMock1967Proxy {
    function implementation() external view returns (address);
    function upgradeToAndCall(address newImplementation, bytes memory data) external;
}

contract Mock1967Proxy is ERC1967Proxy {
    constructor(address implementation_, bytes memory _data) ERC1967Proxy(implementation_, _data) {}

    function implementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }

    function admin() external view returns (address) {
        return ERC1967Utils.getAdmin();
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) external {
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }

    // Allow receiving ETH
    receive() external payable {}
}
