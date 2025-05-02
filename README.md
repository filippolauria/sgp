# Security Group Propagator for Proxmox VE

Security Group Propagator (SGP) is a tool that automates the application of firewall rules in Proxmox VE environments, addressing the lack of native functionality for centralized security policy management.

> **DISCLAIMER**: This is an experimental project. Use at your own risk in production environments. Testing in a non-production environment is strongly recommended before deployment.

## 🔍 The Problem

In Proxmox VE, firewall rules can be configured at different levels (datacenter, node, VM/CT). However, rules configured at the datacenter and node levels only apply to the nodes themselves, not to the VMs and containers running on those nodes. To specify rules for VMs/CTs, you must manually configure them in the firewall section of each individual VM/CT.

This limitation creates several management challenges:

- No centralized management point for VM/CT firewall rules
- Manual configuration required for each VM/CT
- Difficult to maintain consistent security policies across multiple VMs/CTs
- Time-consuming and error-prone process in larger environments
- No automatic way to apply common security policies based on VM/CT characteristics

## 💡 A Possible Solution

SGP offers a possible solution to this limitation by leveraging security groups defined at the datacenter level and automatically linking them to VMs/CTs based on tags. This approach enables:

- Security groups defined once at a centralized level (datacenter)
- Automatic enforcement based on a mapping of tag(s) → security group(s)
- Consistent security group application across multiple VMs/CTs

Essentially, SGP creates the missing link between centrally defined security groups and individual VMs/CTs through tag-based automation, allowing administrators to manage firewall rules efficiently from a single point.

## ✨ Key Features

- **Rule-based Security Group Propagation**: Define rules that link tags to security groups
- **Tag-based Matching**: Apply security groups based on VM/CT tags using "any" or "all" matching criteria
- **Automatic Policy Enforcement**: Set input/output policy for VMs/CTs
- **Positioning Control**: Force security groups to specific positions in the rules list
- **Status-based Application**: Apply rules only to VMs/CTs with specified status (e.g., running)
- **Robust Retry Mechanism**: Handle API operation failures with configurable retry logic
- **Detailed Logging**: Track all actions with comprehensive logging

## 📋 Requirements

- Python 3.6+ (developed and tested with Python 3.11)
- Debian 12 or compatible Linux distribution
- Proxmox VE 6.x+
- API Token with appropriate permissions
- Pre-created security groups in Proxmox VE firewall
- The following Python packages:
  - proxmoxer
  - requests

## 🚀 Installation

Installation (tested on Debian 12):

```bash
# 1. Install git
apt install git

# 2. Clone the repository
git clone https://github.com/filippolauria/sgp.git
cd sgp

# 3. Install dependencies
pip install -r requirements.txt
```

4. Configure the application (see Configuration section below)

## 💻 Development Environment Setup

Execute the steps 1 and 2 from the Installation section above. Then:

```bash
# 1. Install development tools
apt install python3-virtualenv python3-pip

# 2. Create a virtual environment
virtualenv env

# 3. Activate the virtual environment
source env/bin/activate

# 4. Install development dependencies
pip install flake8

# 5. Install required dependencies
pip install -r requirements.txt
```

## ⚙️ Configuration

Create a `config.json` file with the following structure:

```json
{
  "proxmox": {
    "host": "proxmox.example.com",
    "port": 8006,
    "user": "root@pam",
    "token_name": "sgp",
    "token_value": "your-token-uuid",
    "verify_ssl": false
  },
  "retry": {
    "max_attempts": 3,
    "delay_seconds": 1
  },
  "exclude": {
    "node_names": ["node1", "node3"],
    "va_ids": ["100", "101"]
  },
  "rules": [
    {
      "name": "web-servers",
      "tags": {
        "taglist": ["web", "http"],
        "matching": "any"
      },
      "security_groups": ["web_firewall", "basic_protection"],
      "desired_status": ["running"],
      "force_top": true,
      "input_policy": "DROP",
      "output_policy": "ACCEPT"
    },
    {
      "name": "database-servers",
      "tags": {
        "taglist": ["db", "database"],
        "matching": "any"
      },
      "security_groups": ["db_firewall"],
      "desired_status": ["running", "paused"],
      "force_top": true,
      "input_policy": "DROP",
      "output_policy": "ACCEPT"
    }
  ]
}
```

### Important Note

The security groups referenced in the configuration (e.g., `web_firewall`, `basic_protection`, `db_firewall`) **must be created in advance** in the Proxmox VE firewall at the cluster level. SGP does not create the security groups themselves, but rather applies these pre-existing groups to VMs/CTs based on tag matching.

### Configuration Options

#### Proxmox Section
- `host`: Proxmox VE host address
- `port`: API port (default: 8006)
- `user`: Username with permission to access the API
- `token_name`: API token name
- `token_value`: API token value
- `verify_ssl`: Whether to verify SSL certificate (default: false)

#### Retry Section
- `max_attempts`: Maximum number of retry attempts (default: 3)
- `delay_seconds`: Delay between retry attempts in seconds (default: 1)

#### Exclude Section (Optional)
- `node_names`: List of node names to exclude
- `va_ids`: List of VM/CT IDs to exclude

#### Rules Section
Each rule requires:
- `name`: Rule name for identification
- `tags`: 
  - `taglist`: List of tags to match
  - `matching`: Matching type ("any" or "all")
- `security_groups`: List of security groups to apply
- `desired_status`: List of VM/CT statuses to match (e.g., "running", "paused")
- `force_top`: Whether to force the security group to the top of the list
- `input_policy`: Input policy ("ACCEPT" or "DROP")
- `output_policy`: Output policy ("ACCEPT" or "DROP")

## 🏃‍♂️ Usage

Run the script with:

```bash
python sgp.py -c config.json
```

### Command-line Options

- `-c, --config`: Path to configuration file (default: "config.json")
- `-v, --verbose`: Enable verbose output

### Scheduled Execution

For proper operation, SGP should be executed periodically to ensure security groups remain consistent with your defined rules. Set up a scheduled task using cron or a similar tool:

```bash
# Example cron entry (run every minute)
* * * * * /path/to/python /path/to/sgp.py -c /path/to/config.json >> /var/log/sgp.log 2>&1
```

This ensures that:
- New VMs/CTs automatically receive the appropriate security groups
- Any manual changes to firewall rules are restored to the desired state
- VMs/CTs with changed tags get updated security groups

## 📖 How It Works

1. SGP connects to the Proxmox VE API
2. It retrieves all VMs and containers from all nodes (excluding any specified in the configuration)
3. For each VM/CT, it:
   - Checks its tags against the rules
   - If a matching rule is found, applies the specified security groups
   - Ensures the security groups are enabled and positioned correctly
   - Sets the input and output policies

## 🔒 Security Notes

- Create a dedicated API token with minimal permissions
- Regularly backup your firewall configurations
- Test in a non-production environment first
- Consider running as a scheduled task for continuous enforcement

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📚 Proxmox VE Documentation References

- [Proxmox VE Firewall](https://pve.proxmox.com/wiki/Firewall)
- [Proxmox VE API](https://pve.proxmox.com/wiki/Proxmox_VE_API)
- [Proxmox VE Tags](https://pve.proxmox.com/wiki/Tags)

## 📝 TODO

List of future enhancements for this project:

- **Installation Script**: Create an automated installation script to simplify deployment
- **SystemD Integration**: Implement SystemD service and timers instead of cron for more robust scheduling
- **API Digest Handling**: Improve consistent usage of Proxmox API digests throughout the codebase
- **Minimal Permissions**: Document exact minimal permissions required for the API token