// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * 测试合约：演示不同类型的存储变量
 * 用于测试存储布局检测功能
 */
contract StorageLayoutTest {
    // 简单类型变量
    address public owner;           // slot 0
    uint256 public balance;         // slot 1
    bool public isActive;           // slot 2
    
    // mapping 类型（实际槽位需要计算）
    mapping(address => uint256) public balances;  // slot 3 (基础槽位)
    
    // 动态数组（实际元素槽位需要计算）
    address[] public users;         // slot 4 (数组长度存储位置)
    
    // 固定大小数组
    uint256[3] public fixedArray;   // slot 5, 6, 7
    
    // 结构体
    struct User {
        address addr;
        uint256 amount;
        bool active;
    }
    
    mapping(address => User) public userInfo;  // slot 8 (基础槽位)
    
    // 嵌套mapping
    mapping(address => mapping(address => uint256)) public allowances;  // slot 9
    
    constructor() {
        owner = msg.sender;
        isActive = true;
    }
    
    function updateBalance(uint256 newBalance) public {
        require(msg.sender == owner, "Not owner");
        balance = newBalance;
    }
    
    function setUserBalance(address user, uint256 amount) public {
        balances[user] = amount;
    }
}



