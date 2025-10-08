pragma solidity ^0.4.25;

contract SimpleWallet {
    address public owner;
    mapping(address => uint256) public balance;
    uint256 public withdrawLimit;
    
    constructor() public {
        owner = msg.sender;
        withdrawLimit = 1 ether;
    }
    
    function changeOwner(address newOwner) public {
        owner = newOwner;  // 危险：没有访问控制！
    }
    
    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }
    
    function setLimit(uint256 newLimit) public {
        require(msg.sender == owner);
        withdrawLimit = newLimit;
    }
}
