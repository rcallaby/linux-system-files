# Rootkit Detector - How to compile and use

### Use the following to compile the rootkit detector

```bash
make
sudo insmod rk_detector.ko
cat /proc/rootkit_report

```

#### What results can you expecct

| Feature               | Description                                   |
| --------------------- | --------------------------------------------- |
| Hooked Syscalls       | Syscalls overwritten in syscall table         |
| Hidden Kernel Modules | Modules removed from `/proc/modules`          |
| Hidden Processes      | Processes with missing/anonymous executables  |
| Backdoor TCP Sockets  | Listening sockets without userland visibility |
