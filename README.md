# LKM_Rootkit

My attempt at a Kernel Module rootkit. This is heavy influenced by the Diamorphine (https://github.com/m0nad/Diamorphine) rootkit. Listens to signals and will perform actions based on signal number.  
Rootkit will hide any file that matches the 'magic_prefix' -- currently 'rootkit'. This can be toggled with the '63' signals.
```
kill -63 0
```
Rootkit will also change current user contest to uid=0, euid=0, suid=0, and fsuid=0 on the 64 signals
```
kill -64 0
```


#### Features


#### Requirements:
During my testing on an Ubuntu 22-04, I needed to install gcc12  
```
sudo apt update
sudo apt install gcc-12
```

#### Running it
You should then be able to run 'make' inside of the directory
```
make
```

This should make a lot of files, with the most important being 'rootkit.ko'. This is your kernel module. You can insert this by using the insmod command.  
```
sudo insmod root.ko
```

It will automatically hide itself and all files that begin with the name 'rootkit' so you won't be able to simply run a lsmod command. You can send a '63' signal using the kill command to make it unhide everything. It should appear at the top of the kernel module listing as it was recently added.
```
lsmod
kill -63 0
lsmod
```


#### Removing it
You can then remove the module by using the rmmod command. You will need to first unhide it or the system won't be able to see it to remove it.
```
kill -63 0 #if you cannot see it in the lsmod
sudo rmmod rootkit
```

If you make any changes to the code, remember to make clean or you may run into wonky issues
```
make clean
make
```
