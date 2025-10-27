### In development..  
## Kernel module for using FDP SSD 

1. Hooking 'nvme_setup_cmd'
2. Update Placement IDs in background
3. Automatically asign Placement ID

## Make
1. make
2. Module load: insmod fdp_module.ko dev_info="tbytes:lba_sz:chnk_sz:max_ruh:decay_period" dspec_hi16=x
    
    e.g., sudo insmod fdp_module_patch.ko dev_info="107373363200:512:2097152:15:2" dspec_hi16=1
    + dspec_hi16: 0 (FDP Spec) / 1 (NvmeVirt) 
    
3. Module unload: make unload
