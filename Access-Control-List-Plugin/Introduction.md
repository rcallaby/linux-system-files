# Access Control List Plugin

### How to Use

# Compile and load
make
sudo insmod acl_dynamic.ko

# View kernel logs
dmesg | tail

# Dynamically add rules
echo "block_ip 192.168.1.100" | sudo tee /proc/acl_config
echo "block_port 4444" | sudo tee /proc/acl_config
echo "block_uid 1001" | sudo tee /proc/acl_config
