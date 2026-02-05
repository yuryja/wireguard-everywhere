# Changelog - WireGuard Everywhere Installer

## [2026-02-05] - Security and Reliability Improvements

### 🔒 Security Enhancements
- **HTTPS for IP detection**: Changed public IP detection from HTTP to HTTPS using multiple fallback services:
  - Primary: `api.ipify.org`
  - Fallback: `icanhazip.com`
  - Both services tried with `curl` and `wget` for maximum compatibility
  - Prevents MITM attacks during installation

### 🛡️ Input Validation Improvements
- **Port validation**: Now rejects invalid ports (port 0 and negative numbers)
  - Valid range: 1-65535
- **DNS validation**: Custom DNS IPs are now validated to ensure each octet is in the valid range (0-255)
  - Prevents invalid IPs like `999.999.999.999`
  - Provides clearer error messages

### 🐛 Bug Fixes
- **Fixed variable reference**: Corrected `$remove` → `$boringtun_updates` in BoringTun update validation (line 294)
  - This was causing confusing error messages
- **Fixed typo**: Corrected "lenght" → "length" in comment (line 520)

### ⚡ Reliability Improvements
- **Better restart method**: Changed WireGuard restart from `wg-quick down/up` to `systemctl restart`
  - More reliable and follows systemd best practices
  - Consistent with other service management in the script

### 📋 Previous Improvements (Already Implemented)
- Updated minimum OS versions:
  - Ubuntu 22.04+ (was 18.04)
  - Debian 11+ (was 10)
  - CentOS/AlmaLinux/Rocky 9+ (was 7)
- Removed obsolete OS version checks (OpenVZ 6, Fedora 31, etc.)
- Improved container detection with `use_boringtun` variable
- Added DNS providers: Gcore, custom DNS option
- Client name length limited to 15 characters
- Configuration files saved in script directory instead of home
- Improved QR codes with ANSI256UTF8 format
- Added iptables wait flag (`-w 5`) to prevent race conditions
- Simplified OS-specific installation code

## Testing Recommendations

Before deploying to production, test the script on:
- [ ] Ubuntu 22.04 LTS (bare metal)
- [ ] Ubuntu 24.04 LTS (bare metal)
- [ ] Debian 11 (bare metal)
- [ ] Debian 12 (bare metal)
- [ ] AlmaLinux 9 (bare metal)
- [ ] Rocky Linux 9 (bare metal)
- [ ] Ubuntu 22.04 (container/LXC)
- [ ] Debian 12 (container/LXC)

## Known Limitations

- BoringTun (userspace WireGuard) only supports x86_64 architecture in containers
- Requires TUN device availability in containerized environments
- Hardcoded dependency on `https://wg.nyr.be` for BoringTun downloads
  - Consider adding fallback or self-hosting option

## Future Improvements to Consider

1. **Error handling**: Add `set -e` or explicit error checking for critical operations
2. **BoringTun fallback**: Add alternative download sources or self-hosting option
3. **IPv6 DNS**: Add IPv6 DNS servers to DNS provider options
4. **Subnet customization**: Allow users to customize the VPN subnet (currently hardcoded to 10.7.0.0/24)
5. **Logging**: Add optional verbose logging for troubleshooting
6. **Unattended mode**: Add command-line arguments for non-interactive installation
