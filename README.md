# SundanceInH2A

Run iOS 6 on your iPod touch 3 & iPad 1!

Apple never released iOS 6 for iPod touch 3rd-generation (2009) and the original iPad (2010). 13 years later I decided to fix it

This repository contains tools and instructions to *convert* original iOS 6 firmware to iPod touch 3 / iPad 1 compatible firmware and run it untethered

[Demo video on YouTube](https://www.youtube.com/watch?v=VTbShvf97kI)

**Important note**: this is potentially DANGEROUS. Make sure you read this text *very* attentively - especially **Precautions** & **Known issues** sections. I'm not responsible for any damage this tool and knowledge can cause

![](repo/demo.jpg)

## Changelog
<details>

### rev4b
* Added Linux executables (thanks to LukeZGD!)

### rev4a
* Fixed Wi-Fi on Chinese region iPads

### rev4
* iPad 1 support
    * Only iOS 6.1.3 is supported as of now
    * Cellular variant has the baseband disabled and is automatically hactivated

* External resources are now shipped slightly differently, please re-read the tutorial

* iBoot heap metadata is now repaired properly after the exploit
    * ...or at least I hope so

### rev3
* Firmware patch metadata went to separate configs
    * This allows you to use multiple different base IPSW combinations
        * ...and even add your own by filling a corresponding config file

    * Added code to automatically fix code-signature of patched Mach-Os
        * So you don't have to hardcode new page hashes into such configs

* Newly supported configs are iOS 6.1.3 (10B329) & 6.1.6 (10B500)

* Added lock screen overlay image for Wallpaper preference bundle

* Embedded executables now can run on as low as Mac OS X 10.7

### rev2b
* Fixed the bug when unclean shutdown (such as via hard reset) would break the untether

### rev2a
* Fixed Wi-Fi on **CH**-region iPods by disabling WAPI

### rev2
* Added jailbreak option (`-j` flag)

### rev1a
* Fixed the exploit to work on iPod touch 3's with 4096 bytes block size NANDs

* Unlimited `absinthed` & `securekeyvaultd` daemons (were limited to iPhone 3GS by default)
    * They are something related to device attestation, DRM and etc.
    * IDK if it actually improves something, hopefully doesn't break anything at least

### rev1
* Initial release

</details>

## Technical write-up
[Here](https://nyansatan.github.io/run-unsupported-ios)

## Tutorial

### Requirements
* A computer running Mac OS X 10.9+ or a modern Linux distribution
    * 10.8, 10.7 and likely even 10.6 can work as well if you bring `tar` capable of unpacking XZ-compressed archives - for the external resources

* Python 3.7+

* User capable of using terminal

### Prerequisites
* Files from this repository

* Base IPSW - iOS 5.1.1 (9B206)
    * [iPod touch 3](https://secure-appldnld.apple.com/iOS5.1.1/041-4300.20120427.WvgGq/iPod3,1_5.1.1_9B206_Restore.ipsw)
    * [iPad 1](https://secure-appldnld.apple.com/iOS5.1.1/041-4292.02120427.Tkk0d/iPad1,1_5.1.1_9B206_Restore.ipsw)

* Destination iOS 6 IPSW
    * iPod touch 3 uses iPhone 3GS firmwares:
        1. [6.0 (10A403)](https://secure-appldnld.apple.com/iOS6/Restore/041-7173.20120919.sDDMh/iPhone2,1_6.0_10A403_Restore.ipsw)
        2. [6.1.3 (10B329)](https://secure-appldnld.apple.com/iOS6.1/091-2371.20130319.715gt/iPhone2,1_6.1.3_10B329_Restore.ipsw)
        3. [6.1.6 (10B500)](https://secure-appldnld.apple.com/iOS6.1/091-3457.20140221.Btt3e/iPhone2,1_6.1.6_10B500_Restore.ipsw)

    * iPad 1 uses iPad 2 (`iPad2,1`) firmware:
        1. [6.1.3 (10B329)](https://secure-appldnld.apple.com/iOS6.1/091-2397.20130319.EEae9/iPad2,1_6.1.3_10B329_Restore.ipsw)

* Resources that I cannot put straight into this repository - customly assembled kernelcaches & userspace libraries
    * I *heard* that executing this command will yield them:

        macOS:

        ```shell
        cd /path/to/SundanceInH2A
        curl https://gist.githubusercontent.com/NyanSatan/1cf6921821484a2f8f788e567b654999/raw/54c6ad7554710af454c87ec2d99f869e6e669c99/SundanceResources.b64 | base64 -D | tar -xvf -
        ```

        Linux:

        ```shell
        cd /path/to/SundanceInH2A
        curl https://gist.githubusercontent.com/NyanSatan/1cf6921821484a2f8f788e567b654999/raw/54c6ad7554710af454c87ec2d99f869e6e669c99/SundanceResources.b64 | base64 --decode | xz -d | tar -xvf -
        ```

    * This command will write files to `artifacts` and `resources` directories

    * Expected SHA256 hashes:
        ```shell
        ➜  SundanceInH2A git:(master) ✗ shasum -a 256 artifacts/kernelcache.* resources/IMGSGX535GLDriver-*
        b21f9c9578d636ee8353cfd4efade464f02ab5047e1436e98993b7d92fc5d3d0  artifacts/kernelcache.jailbroken.k48ap.bin
        17b230be63bf4760e3098c63316b3c1333a579c2664e0509cd9baac9508ae001  artifacts/kernelcache.jailbroken.n18ap.bin
        e027aef775b4caac00b8c6bd73a8e9e2abedcf2bf6e426eee08ece3ff324cfcd  artifacts/kernelcache.k48ap.bin
        1f7a37b35ca8b1b42813a9e7773726f10faf9b0c0b0bacbc6057ecd6ab9d244d  artifacts/kernelcache.n18ap.bin
        6d2c965af511996f9717797978a50be7e0f47753d42b538e20693bd2e1b8cede  resources/IMGSGX535GLDriver-600
        a3ce15a1d46480bfd6757e6a4db38b1b3b0c6a9dcd50cbdda1c9b8bb55a1f8d8  resources/IMGSGX535GLDriver-610
        ```

* Pwned DFU tool
    * For modern Mac OS X (11.x Big Sur+) I recommend [iPwnder32](https://github.com/dora2ios/iPwnder32) by **dora2ios**
    * For older ones [ipwndfu](https://github.com/axi0mX/ipwndfu) by **axi0mX** should do fine
    * For Linux, use this version of [iPwnder](https://github.com/LukeZGD/iPwnder32)

### Steps

0. This repository contains precompiled executables that I built statically for your convenience ("statically" in terms of external dependencies). Modern Mac OS X might put them on quarantine and refuse to run them. To get rid of this restriction, remove extended attributes from all the files in `executables/`

    ```shell
    ➜  SundanceInH2A git:(master) ✗ xattr -cr executables
    ```

1. Change working directory to the downloaded repo and execute:

    ```shell
    ➜  SundanceInH2A git:(master) ✗ ./Sundancer iOS511.ipsw iOS6.ipsw CUSTOM_BUNDLE
    ```

    Where `iOS511.ipsw` is the original iOS 5.1.1, `iOS6.ipsw` is base iOS 6.x IPSW (check **Prerequisites** section) and finally `CUSTOM_BUNDLE` is a directory that will contain custom firmware

    Add `-j` option to apply jailbreak

    If it all goes well, after 30 seconds (or up to 3-4 minutes on older hardware) restore bundle will be ready. *Bundle* as in sort-of unpacked IPSW (luckily, modern `idevicerestore` can process those)

    Log sample:

    ```shell
    ➜  SundanceInH2A git:(feat-ipad-1) ✗ ./Sundancer iPod3,1_5.1.1_9B206_Restore.ipsw iPhone2,1_6.0_10A403_Restore.ipsw iPod3,1_6.0_10A403_Custom
    |  0.003 |  processing iOS 5 iBoots
    |  0.015 |  packaging kernelcache
    |  1.186 |  packaging DeviceTree
    |  1.191 |  extracting iOS 5 root filesystem
    |  3.995 |  extracting WLAN & multitouch firmwares
    |  4.021 |  extracting Bluetooth firmware
    |  4.031 |  extracting iOS 6 root filesystem
    |  7.718 |  removing OTA update files
    |  7.852 |  patching files
    |  8.247 |  unlimiting com.apple.absinthed.N88.plist LaunchDaemon
    |  8.282 |  unlimiting com.apple.fairplayd.N88.plist LaunchDaemon
    |  8.298 |  unlimiting com.apple.securekeyvaultd.N88.plist LaunchDaemon
    |  8.316 |  adding Hactivator
    |  8.483 |  packaging iOS 6 root filesystem
    | 33.086 |  extracting iOS 6 ramdisk
    | 33.149 |  growing ramdisk
    | 33.168 |  replacing rc.boot
    | 33.179 |  putting exploit.dmg
    | 33.186 |  patching options plist
    | 33.203 |  packaging iOS 6 ramdisk
    | 33.212 |  assembling bundle
    | 33.301 |  wrote BuildManifest
    | 33.308 |  DONE!
    ```

2. Enter pwned DFU on your device
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

    macOS:

    ```shell
    ➜  SundanceInH2A git:(master) ✗ executables/$(uname)/idevicerestore -ey CUSTOM_BUNDLE
    ```

    Linux:

    ```shell
    ➜  SundanceInH2A git:(master) ✗ executables/$(uname)/$(uname -m)/idevicerestore -ey CUSTOM_BUNDLE
    ```

Restore is going to take around 5 minutes. If everything goes well, you'll end up on iOS 6 setup screen

Please note that iOS 6 is very ancient at this point, so most online services (both Apple's and 3rd-party) are not gonna work. You can still activate the device though

## Downgrade tutorial
The iBoot exploit used for the untether needs `boot-partition` NVRAM variable set to `2` to activate. It will break iOS 5.1.1 if set this way, and old iOS versions are dumb enough to NOT erase the variable upon restore

I patched iBEC to allow arbitrary NVRAM variable change, so you can remove it without much hassle

1. Create a custom iOS 6 restore bundle if not already

2. Enter pwned DFU

3. Start a restore, but kill `idevicerestore` immediately after it finished uploading iBEC

4. Your device should light up its' display and appear on USB

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

`amfi=0xff` and `launchctl_enforce_codesign=0` are always added automatically by the exploit's shellcode to disable Mach-O codesigning and LaunchDaemon signed cache (on iOS 6.1.x)

## Precautions

* This is unholy mix of DEVELOPMENT kernel, DeviceTree diffs and custom iBoot patches - I highly doubt anything *bad* can happen, but...

* Wi-Fi, Bluetooth & multitouch firmwares are taken from iOS 5 - they seem to behave sanely, but...

* Even though I tested it quite well, there still might be various issues. Let me know if you find any

* iPad 1 with Cellular will have baseband disabled and device activation broken
    * Hactivation is implemented for such case, though

* This tool uses an iBoot bug (HFS+ extent buffer overflow) to make it run untethered. I never encountered any issues with the current implementation of the exploit, but they still might happen making your device enter a boot loop - nothing irreversible though - see **Downgrade tutorial**

## Known issues

* Sometimes, Wi-Fi reconnects every minute or so
    * Might be related to my router

* Built-in speaker seems to be less loud compared to iOS 5
    * Headphones work fine
    * Probably related to missing hardware-specific plists in `MediaToolbox` framework

* Bluetooth audio devices cannot actually play
    * Seems to be related to `VirtualAudio` bundle, and it's a mess

## Credits

* **planetbeing**, **dborca**, **xerub** - for XPwn tools
* **pimskeks** and other people behind **libimobiledevice** project - for libirecovery & idevicerestore
* **LukeZGD** - for pre-compiled Linux executables
* Whoever assembled the jailbreak bootstrap tarball, I personally stole it from [**aquila**](https://github.com/staturnzz/aquila)
