import os
import subprocess
import re

class WireGuardManager:
    def __init__(self, config_path, clients_dir):
        self.config_path = config_path
        self.clients_dir = clients_dir
        
        # Ensure clients directory exists
        if not os.path.exists(self.clients_dir):
            os.makedirs(self.clients_dir)

    def run_command(self, command):
        """Run a shell command and return output"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception(f"Command failed: {e.stderr}")

    def get_server_config(self):
        """Read server configuration mostly for Endpoint and DNS info"""
        if not os.path.exists(self.config_path):
            raise Exception(f"Config file not found: {self.config_path}")
            
        with open(self.config_path, 'r') as f:
            content = f.read()
            
        # Extract ListenPort
        port_match = re.search(r'ListenPort\s*=\s*(\d+)', content)
        port = port_match.group(1) if port_match else "51820"
        
        # Extract Endpoint (from comments added by install.sh)
        endpoint_match = re.search(r'# ENDPOINT\s+(.+)', content)
        if endpoint_match:
            endpoint = endpoint_match.group(1).strip()
        else:
            # Fallback: Try to detect public IP automatically
            try:
                endpoint = self.run_command("curl -s -4 https://api.ipify.org || wget -qO- -4 https://api.ipify.org").strip()
                if not endpoint or not re.match(r'^[0-9.]+$', endpoint):
                    endpoint = "SERVER_IP"
            except:
                endpoint = "SERVER_IP"
        
        # Get server public key
        # We need to run wg show because private key is in config, not public
        try:
            # Try to get from running interface first
            server_pubkey = self.run_command("wg show wg0 public-key")
        except:
            # Fallback: create from private key in config
            privkey_match = re.search(r'PrivateKey\s*=\s*(.+)', content)
            if privkey_match:
                privkey = privkey_match.group(1)
                server_pubkey = self.run_command(f"echo '{privkey}' | wg pubkey")
            else:
                server_pubkey = "UNKNOWN_KEY"
                
        return {
            'port': port,
            'endpoint': endpoint,
            'public_key': server_pubkey
        }

    def get_next_ip(self):
        """Calculate next available IP address"""
        with open(self.config_path, 'r') as f:
            content = f.read()
            
        # Find all used last octets for 10.7.0.x
        # Matches AllowedIPs = 10.7.0.X/32
        used_octets = re.findall(r'AllowedIPs\s*=\s*10\.7\.0\.(\d+)/32', content)
        used_octets = [int(o) for o in used_octets]
        
        # Find lowest available octet starting from 2
        octet = 2
        while octet in used_octets:
            octet += 1
            
        if octet > 254:
            raise Exception("No more IP addresses available in 10.7.0.0/24 subnet")
            
        return f"10.7.0.{octet}"

    def create_client(self, name):
        """Create a new client configuration"""
        # Generate keys
        private_key = self.run_command("wg genkey")
        public_key = self.run_command(f"echo '{private_key}' | wg pubkey")
        psk = self.run_command("wg genpsk")
        
        # Get next IP
        ip_address = self.get_next_ip()
        
        # Get server details
        server_conf = self.get_server_config()
        
        # Create client config
        # Check if IPv6 is enabled in server config to add it to client
        has_ipv6 = "fddd:2c4:2c4:2c4::1" in open(self.config_path).read()
        ipv6_str = ""
        if has_ipv6:
            # Last octet of IPv4 is used for IPv6 suffix as well
            octet = ip_address.split('.')[-1]
            ipv6_str = f", fddd:2c4:2c4:2c4::{octet}/64"
        
        # Default DNS
        # Check if DNS comment exists from install.sh
        # For now, default to Google DNS if not found
        dns = "8.8.8.8, 8.8.4.4"
        
        client_config = f"""[Interface]
Address = {ip_address}/24{ipv6_str}
DNS = {dns}
PrivateKey = {private_key}

[Peer]
PublicKey = {server_conf['public_key']}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_conf['endpoint']}:{server_conf['port']}
PersistentKeepalive = 25
"""
        
        # Save client config file
        config_path = os.path.join(self.clients_dir, f"{name}.conf")
        with open(config_path, 'w') as f:
            f.write(client_config)
            
        # Add peer to server config
        ipv6_allowed = ""
        if has_ipv6:
            octet = ip_address.split('.')[-1]
            ipv6_allowed = f", fddd:2c4:2c4:2c4::{octet}/128"
            
        peer_block = f"""
# BEGIN_PEER {name}
[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {ip_address}/32{ipv6_allowed}
# END_PEER {name}
"""
        with open(self.config_path, 'a') as f:
            f.write(peer_block)
            
        # Add to running interface without restarting
        # We need to format specific for `wg set` or `wg addconf`
        # Using `wg addconf` is safer/easier with a temp file
        temp_conf = f"""[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {ip_address}/32{ipv6_allowed}
"""
        temp_path = f"/tmp/wg_new_peer_{name}.conf"
        with open(temp_path, 'w') as f:
            f.write(temp_conf)
            
        try:
            self.run_command(f"wg addconf wg0 {temp_path}")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
        return {
            'public_key': public_key,
            'ip_address': ip_address,
            'config_path': config_path
        }

    def delete_client(self, name):
        """Remove a client"""
        # Read current config
        with open(self.config_path, 'r') as f:
            lines = f.readlines()
            
        # Remove block from config file
        new_lines = []
        is_in_block = False
        public_key = None
        
        for line in lines:
            if line.strip() == f"# BEGIN_PEER {name}":
                is_in_block = True
                continue
            
            if is_in_block:
                if "PublicKey" in line:
                    public_key = line.split("=")[1].strip()
                if line.strip() == f"# END_PEER {name}":
                    is_in_block = False
                continue
                
            new_lines.append(line)
            
        with open(self.config_path, 'w') as f:
            f.writelines(new_lines)
            
        # Remove from running interface
        if public_key:
            try:
                self.run_command(f"wg set wg0 peer {public_key} remove")
            except:
                pass # Peer might not be active
                
        # Remove client config file
        config_path = os.path.join(self.clients_dir, f"{name}.conf")
        if os.path.exists(config_path):
            os.remove(config_path)

    def enable_client(self, name):
        """Enable a client (add peer back to running interface)"""
        # Simply retrieve peer info from config and add it
        # This is complex parsing, so we'll re-read the block from file
        with open(self.config_path, 'r') as f:
            content = f.read()
            
        # Extract block
        pattern = re.compile(f"# BEGIN_PEER {name}(.*?)# END_PEER {name}", re.DOTALL)
        match = pattern.search(content)
        
        if match:
            peer_block = match.group(1).strip()
            
            # Create temp file for addconf
            temp_path = f"/tmp/wg_enable_peer_{name}.conf"
            with open(temp_path, 'w') as f:
                f.write(peer_block)
                
            try:
                self.run_command(f"wg addconf wg0 {temp_path}")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            raise Exception("Client configuration not found in wg0.conf")

    def disable_client(self, name):
        """Disable a client (remove peer from running interface but keep in config)"""
        # Find public key from config file
        with open(self.config_path, 'r') as f:
            content = f.read()
            
        pattern = re.compile(f"# BEGIN_PEER {name}.*?PublicKey\s*=\s*([^\n]+)", re.DOTALL)
        match = search = pattern.search(content)
        
        if match:
            public_key = match.group(1).strip()
            self.run_command(f"wg set wg0 peer {public_key} remove")
        else:
            raise Exception("Client configuration not found")

    def get_client_config(self, name):
        """Get content of client configuration file"""
        config_path = os.path.join(self.clients_dir, f"{name}.conf")
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return f.read()
        return None
        
    def get_client_config_path(self, name):
        return os.path.join(self.clients_dir, f"{name}.conf")
