# Ubuntu Security Hardening Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-18.04%20|%2020.04%20|%2022.04%20|%2024.04%20LTS-orange)](https://ubuntu.com/)
[![Bash](https://img.shields.io/badge/Bash-5.0%2B-green)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-Hardening-blue)](https://github.com/alokemajumder)

Production-grade security hardening scripts for Ubuntu systems that implement comprehensive security controls, compliance configurations, and system hardening based on industry best practices.

## 🚀 Features

### Core Security Implementations
- **System Updates**: Automated security patching with unattended-upgrades
- **File Integrity Monitoring**: AIDE configuration with scheduled checks
- **Audit System**: Comprehensive auditd rules for security monitoring
- **Access Control**: AppArmor MAC enforcement
- **Antivirus**: ClamAV with scheduled scanning
- **Firewall**: UFW with secure defaults and rate limiting
- **Intrusion Prevention**: Fail2ban with SSH and port scan protection
- **SSH Hardening**: Crypto hardening, key-only authentication
- **Kernel Security**: Sysctl hardening parameters
- **System Limits**: Resource restrictions and core dump prevention

### Additional Security Tools
- **Rootkit Detection**: rkhunter and chkrootkit
- **Security Auditing**: Lynis and Tiger
- **Compliance Scanning**: OpenSCAP with CIS benchmarks
- **Network Monitoring**: arpwatch and netstat analysis
- **Package Verification**: debsums integrity checking

## 📋 Requirements

### System Requirements
- Ubuntu 18.04 LTS, 20.04 LTS, 22.04 LTS, or 24.04 LTS
- Minimum 2GB free disk space
- Minimum 1GB RAM (2GB recommended)
- Root or sudo access
- Active internet connection for package downloads

### Pre-Installation Checklist
- [ ] Create a system backup or VM snapshot
- [ ] Ensure SSH key access is configured (password auth will be disabled)
- [ ] Document any custom configurations
- [ ] Note required firewall ports for your services
- [ ] Have console access ready (in case of SSH issues)

## 🔧 Installation

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gensecaihq/ubuntu-security-hardening-script.git
   cd ubuntu-security-hardening-script
   ```

2. **Make scripts executable:**
   ```bash
   chmod +x ubuntu-hardening-*.sh
   ```

3. **Run the appropriate script:**

   **For Ubuntu 18.04/20.04/22.04:**
   ```bash
   sudo ./ubuntu-hardening-original.sh
   ```

   **For Ubuntu 24.04 LTS:**
   ```bash
   sudo ./ubuntu-hardening-24.04.sh
   ```

### Advanced Installation

**With logging to file:**
```bash
sudo ./ubuntu-hardening-original.sh 2>&1 | tee hardening-install.log
```

**Test mode (Ubuntu 24.04):**
```bash
sudo ./ubuntu-hardening-24.04.sh --test  # Coming soon
```

## 📚 Script Versions

### ubuntu-hardening-original.sh
Designed for Ubuntu 18.04 LTS through 22.04 LTS with:
- Traditional cron-based scheduling
- Compatible with older package versions
- Standard systemd configurations
- Legacy-friendly security controls

### ubuntu-hardening-24.04.sh
Optimized for Ubuntu 24.04 LTS (Noble Numbat) with:
- Systemd timers for all scheduled tasks
- Ubuntu Pro/Advantage integration
- Enhanced snap confinement
- Modern cryptographic defaults
- Advanced systemd security features
- Netplan and systemd-resolved hardening

## 🛡️ Security Controls Applied

### 1. Authentication & Access
- SSH root login disabled
- Password authentication disabled
- PAM password quality enforcement
- Login attempt limits
- Session timeout configuration

### 2. Network Security
- Default deny firewall policy
- Rate-limited SSH access
- IPv6 security (configurable)
- TCP SYN flood protection
- ICMP redirect prevention

### 3. System Integrity
- Daily file integrity checks
- Comprehensive audit logging
- Secure kernel parameters
- Module loading restrictions
- Core dump prevention

### 4. Monitoring & Detection
- Real-time intrusion detection
- Rootkit scanning
- Virus scanning with quarantine
- Security compliance scanning
- Automated log analysis

## ⚙️ Configuration

### During Installation
The scripts will prompt for:
- ClamAV scan frequency (daily/weekly/monthly)
- OpenSCAP scan frequency (daily/weekly/monthly)

### Post-Installation Configuration

**Add firewall rules for services:**
```bash
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw status verbose
```

**Modify automatic update settings:**
```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

**Adjust SSH settings:**
```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
sudo systemctl restart sshd
```

## 📊 Monitoring & Maintenance

### View Security Reports
```bash
# Hardening report
sudo cat /var/log/security-hardening/hardening_report_*.txt

# Audit summary
sudo aureport --summary

# Failed login attempts
sudo aureport --auth --failure

# File integrity check
sudo aide --check
```

### Security Scanning Commands
```bash
# System audit
sudo lynis audit system

# Rootkit check
sudo rkhunter -c

# Compliance scan (Ubuntu 24.04)
sudo /usr/local/bin/openscap-scan.sh

# Check service status
sudo systemctl status auditd apparmor ufw fail2ban
```

### Log Locations
- **Hardening logs**: `/var/log/security-hardening/`
- **Audit logs**: `/var/log/audit/audit.log`
- **ClamAV logs**: `/var/log/clamav/`
- **UFW logs**: `/var/log/ufw.log`
- **Fail2ban logs**: `/var/log/fail2ban.log`

## 🚨 Important Warnings

### ⚠️ SSH Access
- **Password authentication is DISABLED** after hardening
- Ensure SSH key access is working before running the script
- Test SSH key access from another terminal before disconnecting
- Keep a console/physical access method available

### ⚠️ Firewall Rules
- Only SSH (port 22) is allowed by default
- All other incoming connections are blocked
- Add rules for your required services post-installation

### ⚠️ System Impact
- Some applications may be affected by kernel hardening
- Test all critical services after hardening
- Review the hardening report for applied changes
- Some parameters may need adjustment for specific workloads

## 🔄 Updates and Maintenance

### Automatic Updates
The system is configured for automatic security updates. To check status:
```bash
sudo systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --debug
```

### Manual Security Updates
```bash
# Update package lists
sudo apt update

# Upgrade packages
sudo apt upgrade

# Update virus definitions
sudo freshclam

# Update rootkit definitions
sudo rkhunter --update
```

## 📈 Compliance and Standards

The scripts implement controls based on:
- CIS Ubuntu Linux Benchmarks
- NIST Cybersecurity Framework
- PCI DSS Requirements (where applicable)
- Common security best practices

For compliance scanning:
```bash
# List available profiles
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu*.xml

# Run specific compliance check
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --report /tmp/cis-report.html \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu*.xml
```

## 🐛 Troubleshooting

### SSH Connection Issues
```bash
# If locked out, use console access and:
sudo ufw allow ssh
sudo systemctl restart sshd
sudo fail2ban-client stop sshd
```

### Service Failures
```bash
# Check service status
sudo systemctl status <service-name>

# View service logs
sudo journalctl -u <service-name> -n 50

# Restart service
sudo systemctl restart <service-name>
```

### Performance Issues
```bash
# Disable ClamAV daemon if needed
sudo systemctl stop clamav-daemon
sudo systemctl disable clamav-daemon

# Adjust audit rules if too verbose
sudo auditctl -l  # List rules
sudo auditctl -D  # Delete all rules
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

### Development Guidelines
- Test scripts in isolated VMs
- Document any new features
- Follow existing code style
- Update this README for new functionality

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Disclaimer

These scripts are provided "AS IS" without warranty of any kind. Always test in a non-production environment first. The authors are not responsible for any damage or data loss resulting from the use of these scripts.

## 🙏 Acknowledgments

- Ubuntu Security Team for security guidelines
- CIS for benchmark documentation
- Open source security tool maintainers
- Community contributors and testers

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/ubuntu-security-hardening-script/issues)


## 🔗 Useful Resources

- [Ubuntu Security Documentation](https://ubuntu.com/security)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
- [OpenSCAP Documentation](https://www.open-scap.org/documentation/)

---
