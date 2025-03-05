### // In development  
## Kernel module for using FDP SSD 

1. Hooking 'nvme_setup_rw'
2. Update Placement IDs in background
3. Automatically asign Placement ID to cmd->dspec
4. Need to custom kernel (uname -r: 6.2.0-custom)
5. modprobe fdp_module dev_info="tbytes:lba_sz:chnk_sz:max_ruh:decay_period"
