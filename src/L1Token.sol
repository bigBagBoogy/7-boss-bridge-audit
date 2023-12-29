// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract L1Token is ERC20 {
    uint256 private constant INITIAL_SUPPLY = 1_000_000;

    constructor() ERC20("BossBridgeToken", "BBT") {
        _mint(msg.sender, INITIAL_SUPPLY * 10 ** decimals());
    }
}
//                 bigBagBoogy y'all!!!!!

//               /$$$$$$$  /$$$$$$$  /$$$$$$$
//              | $$__  $$| $$__  $$| $$__  $$
//              | $$  \ $$| $$  \ $$| $$  \ $$
//              | $$$$$$$ | $$$$$$$ | $$$$$$$
//              | $$__  $$| $$__  $$| $$__  $$
//              | $$  \ $$| $$  \ $$| $$  \ $$
//              | $$$$$$$/| $$$$$$$/| $$$$$$$/
//              |_______/ |_______/ |_______/

// made at:  https://patorjk.com/software/taag/#p=display&h=0&v=1&f=Big%20Money-ne&t=BBB
