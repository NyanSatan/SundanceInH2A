# SundanceInH2A

Run iOS 6 on your iPod touch 3!

Apple never released iOS 6 for iPod touch 3rd-generation (2009). 13 years later I decided to fix it

This repository contains tools and instructions to *convert* iPhone 3GS iOS 6.0 (10A403) firmware to iPod touch 3 compatible firmware and run it untethered

[Demo video on YouTube](https://www.youtube.com/watch?v=VTbShvf97kI)

**Important note**: this is potentially DANGEROUS. Make sure you read this text *very* attentively - especially **Precautions** & **Known issues** sections. I'm not responsible for any damage this tool and knowledge can cause

![](repo/demo.jpg)

## Technical write-up
[Here](https://nyansatan.github.io/run-unsupported-ios)

## Tutorial

### Requirements
* A computer running Mac OS X 10.8+
    * Easy to port to Linux and even Windows - basically, you need to recompile everything under `executables/` for these platforms

* Python 3.7+

* User capable of using terminal

### Prerequisites
* Files from this repository

* iPhone 3GS iOS 6.0 (10A403) [IPSW](https://secure-appldnld.apple.com/iOS6/Restore/041-7173.20120919.sDDMh/iPhone2,1_6.0_10A403_Restore.ipsw)

* iPod touch 3 iOS 5.1.1 (9B206) [IPSW](https://secure-appldnld.apple.com/iOS5.1.1/041-4300.20120427.WvgGq/iPod3,1_5.1.1_9B206_Restore.ipsw)

* iOS 6 kernelcache for iPod touch 3
    * This was never published by Apple in any form, but it's doable to assemble it from internal iOS 6 builds. Instructions eta son, but for time being... I *heard* that executing this command will yield a good kernelcache you can feed to this tool:

        ```shell
        curl https://gist.githubusercontent.com/NyanSatan/1cf6921821484a2f8f788e567b654999/raw/7fa62c2cb54855d72b2a91c2aa3d57cab7318246/magic-A63970m.b64 | base64 -D | gunzip > kernelcache.n18ap.bin
        ```

    * Put it into `artifacts/kernelcache.n18ap.bin`

    * Expected SHA256 hash:
        ```shell
        ➜  SundanceInH2A git:(master) ✗ shasum -a 256 artifacts/kernelcache.n18ap.bin 
        1f7a37b35ca8b1b42813a9e7773726f10faf9b0c0b0bacbc6057ecd6ab9d244d  artifacts/kernelcache.n18ap.bin
        ```
* Pwned DFU tool
    * For modern Mac OS X (11.x Big Sur+) I recommend [iPwnder32](https://github.com/dora2ios/iPwnder32) by **dora2ios**
    * For older ones [ipwndfu](https://github.com/axi0mX/ipwndfu) by **axi0mX** should do fine

### Steps

0. This repository contains precompiled executables that I built statically for your convinience ("statically" in terms of external dependencies). Modern Mac OS X might put them on quarantine and refuse to run them. To get rid of this restriction, remove extended attributes from all the files in `executables/`

    ```shell
    ➜  SundanceInH2A git:(master) ✗ xattr -cr executables
    ```

1. Change working directory to the downloaded repo and execute:

    ```shell
    ➜  SundanceInH2A git:(master) ✗ ./Sundancer iPod3,1_5.1.1_9B206_Restore.ipsw iPhone2,1_6.0_10A403_Restore.ipsw iPod3,1_6.0_10A403_Custom
    ```

    Change the paths accordingly, of course

    If it all goes well, after 30 seconds (or up to 3-4 minutes on older hardware) you will see a new directory - `iPod3,1_6.0_10A403_Custom`. This is our new restore bundle - basically an unpacked IPSW (luckily, modern `idevicerestore` can process those)

    Log sample:

    ```shell
    ➜  SundanceInH2A git:(master) ✗ ./Sundancer iPod3,1_5.1.1_9B206_Restore.ipsw iPhone2,1_6.0_10A403_Restore.ipsw iPod3,1_6.0_10A403_Custom
    |  0.002 |  processing iOS 5 iBoots
    |  0.014 |  packaging kernelcache
    |  1.183 |  packaging DeviceTree
    |  1.187 |  extracting iOS 5 root filesystem
    |  3.938 |  extracting WLAN & multitouch firmwares
    |  3.963 |  extracting Bluetooth firmware
    |  3.971 |  extracting iOS 6 root filesystem
    |  7.567 |  removing OTA update files
    |  7.703 |  patching dyld shared cache
    |  8.094 |  patching FairPlay LaunchDaemon
    |  8.265 |  packaging iOS 6 root filesystem
    | 32.929 |  extracting iOS 6 ramdisk
    | 32.985 |  growing ramdisk
    | 32.987 |  patching ASR
    | 33.002 |  replacing rc.boot
    | 33.014 |  putting exploit.dmg
    | 33.021 |  moving options plist
    | 33.024 |  packaging iOS 6 ramdisk
    | 33.033 |  assembling bundle
    | 33.129 |  wrote BuildManifest
    | 33.132 |  DONE!
    ```

2. Enter pwned DFU on your iPod touch 3
    1. First, enter normal bootrom DFU (involves pressing and holding Home and Power buttons - there are plenty of guides online)
    2. Then run either **iPwnder** or **ipwndfu** with `-p` flag

    ```shell
    ➜  SundanceInH2A git:(master) ✗ iPwnder32 -p
    ** iPwnder32 - RELEASE v3.2.0 [3C152] by @dora2ios
    Waiting for device in DFU mode...
    DFU device infomation iPod Touch (3rd gen) [iPod3,1]
    CPID:0x8922 CPRV:0x02 BDID:0x02 ECID:0xXXXXXXXXXXXXXXXX CPFM:0x03 SCEP:0x01 IBFL:0x00
    SRTG:[iBoot-359.5] 
    exploiting with limera1n
    * based on limera1n exploit (heap overflow) by geohot
    Device is now in pwned DFU mode!
    ```

3. Start restore! `idevicerestore` is provided by this repo under `executables/`

    ```shell
    ➜  SundanceInH2A git:(master) ✗ executables/idevicerestore -ey iPod3,1_6.0_10A403_Custom
    ```

Restore is going to take around 5 minutes. If everything goes well, you'll end up on iOS 6 setup screen

Please note that iOS 6 is very ancient at this point, so most online services (both Apple's and 3rd-party) are not gonna work. You can still activate the device though

## Downgrade tutorial
The iBoot exploit used for the untether needs `boot-partition` NVRAM variable set to `2` to activate. It will break iOS 5.1.1 if set this way, and old iOS versions are dumb enough to NOT erase the variable upon restore

I patched iBEC to allow arbitrary NVRAM variable change, so you can remove it without much hassle

1. Create a custom iOS 6 restore bundle if not already

2. Enter pwned DFU

3. Start a restore, but kill `idevicerestore` immediately after it finished uploading iBEC

4. Your iPod should light up its' display and appear on USB

5. Now you need `irecovery` which is included in `executables/`

    ```shell
    # reset the variable
    irecovery -c "setenv boot-partition"

    # synchronize NVRAM
    irecovery -c "saveenv"

    # reboot the device
    irecovery -c "reboot"
    ```

6. At this point, the variable should have gone away and you can restore iOS 5.1.1

## Boot-args/verbose boot
The iBoot exploit makes it respect NVRAM boot-args, so you can set `-v` to make kernel print boot logs to screen, for instance

Enter recovery mode and execute commands below:

```shell
# set desired args
irecovery -c "setenv boot-args -v"

# synchronize NVRAM
irecovery -c "saveenv"

# set "auto-boot" to "true" and reboot the device
irecovery -n
```

`amfi=0xff` is added automatically by the exploit's shellcode to disable codesigning

## Precautions

* This is unholy mix of DEVELOPMENT kernel, DeviceTree diffs and custom iBoot patches - I highly doubt anything *bad* can happen, but...

* Wi-Fi, Bluetooth & multitouch firmwares are taken from iOS 5 - they seem to behave sanely, but...

* Even though I tested it quite well, there still might be various issues. Let me know if you find any

* This tool uses an iBoot bug (HFS+ extent buffer overflow) to make it run untethered. I never encountered any issues with the current implementation of the exploit, but they still might happen making your device enter a boot loop - nothing irreversible though - see **Downgrade tutorial**

## Known issues

* Some Wi-Fi networks cannot be joined, however they cannot be joined on iOS 5.1.1 either

* Built-in speaker seems to be less loud compared to iOS 5
    * Headphones work fine
