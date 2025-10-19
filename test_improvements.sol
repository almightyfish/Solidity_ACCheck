// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

/**
 * 测试合约：用于验证改进后的污点分析工具
 * 
 * 包含以下场景：
 * 1. 带modifier的安全函数（应被识别为安全）
 * 2. 无保护的危险函数（应被识别为危险）
 * 3. 多重modifier（测试复杂条件检测）
 * 4. 内联条件检查（测试字节码层面的检测）
 */
contract TestImprovements {
    address public owner;
    uint256 public balance;
    bool public paused;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }
    
    modifier validAddress(address addr) {
        require(addr != address(0), "Invalid address");
        _;
    }
    
    constructor() public {
        owner = msg.sender;
        balance = 0;
        paused = false;
    }
    
    // ✅ 场景1：单个modifier保护（应被识别为安全）
    function setOwner_Safe(address newOwner) public onlyOwner {
        owner = newOwner;  // ← 应标记为：可疑（medium），双重检测通过
    }
    
    // ❌ 场景2：无保护的危险函数（应被识别为危险）
    function setOwner_Dangerous(address newOwner) public {
        owner = newOwner;  // ← 应标记为：危险（low），无任何保护
    }
    
    // ✅ 场景3：多重modifier（测试复杂CFG）
    function withdraw_MultiProtected(uint amount) public 
        onlyOwner 
        whenNotPaused 
    {
        require(balance >= amount, "Insufficient balance");
        balance -= amount;  // ← 应标记为：可疑（high），多重保护
    }
    
    // ⚠️ 场景4：内联条件检查（测试字节码检测）
    function updateBalance_InlineCheck(uint amount) public {
        // 内联的访问控制（不是modifier）
        if (msg.sender == owner) {
            balance += amount;  // ← 应标记为：可疑（medium），有条件但不是modifier
        }
    }
    
    // ⚠️ 场景5：require保护（测试字节码revert检测）
    function setBalance_RequireProtected(uint newBalance) public {
        require(msg.sender == owner, "Not owner");
        balance = newBalance;  // ← 应标记为：可疑（medium），有require
    }
    
    // ❌ 场景6：条件不充分（测试误报）
    function setPaused_WeakCheck(bool _paused) public {
        // 弱检查：只检查非零地址，但不检查是否是owner
        if (msg.sender != address(0)) {
            paused = _paused;  // ← 应标记为：危险或可疑（low/medium），条件不充分
        }
    }
    
    // ✅ 场景7：view函数（应被自动排除）
    function getOwner() public view returns (address) {
        return owner;  // ← 不应标记为风险（view函数不修改状态）
    }
    
    // ✅ 场景8：fallback函数（应被自动排除）
    function() public payable {
        balance += msg.value;  // ← 不应标记为风险（fallback用于接收以太币）
    }
}




