cmd_/home/yongsang/fdp_module/fdp_module.mod := printf '%s\n'   fdp_module.o | awk '!x[$$0]++ { print("/home/yongsang/fdp_module/"$$0) }' > /home/yongsang/fdp_module/fdp_module.mod
