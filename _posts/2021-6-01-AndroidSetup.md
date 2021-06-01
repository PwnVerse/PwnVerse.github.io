---
layout: "post"
title: "Setting up Android debugging"
date: 2021-6-01
tags: [Android,Setup]
---

I've been meaning to learn some android exploitation for quite sometime now. In this post , I propose to document the method of setting up a proper debugging environment (for self reference too) to debug android applications with the good old GDB.

# Pre-requisites

+ Download and install latest version of Android Studio by following this wonderful [blog](https://linuxize.com/post/how-to-install-android-studio-on-ubuntu-18-04/).

+ For basic creating android virtual emulator , follow this [blog](https://developer.android.com/studio/run/managing-avds).

Now that everything is ready and set , let's get to some business.

# Making system writeable

To run `gdbserver` on our device , we need to first make the `/system` folder writeable, by default , it is read-only.

By default , even if we run `adb` as root , a couple of times , while trying to mount `/system` as writeable we're hit with the `/system not in /proc/mounts` as the `/system` partition is made `read only` in the very booting up of the emulator itself.

To fix that ,we fire up the emulator with `-writable system` flag , and then we can remount system as writeable with adb root.

To view list of active devices , run

```sh
adb-devices
```

The output should look something like this since we have just one device connected.

```sh
List of devices attached
emulator-5554	device
```

You can simply get into the device with 

```sh
abd -s emulator-5554 shell
```

Note that `emulator-5554` is to be replaced with the name of the device we wish to connect to.

To get a list of all active emulators , navigate to the `/path/to/Android/Sdk/` and run - 

```sh
~/Android/Sdk/tools ❯ ./emulator -list-avds

Cyb0rG
Pixel_3a_API_30_x86

```

The output should be something similar.

Now , to fire up our emulator with writeable system , run

```sh
./emulator -avd Cyb0rG -writable-system
```

Again , `Cyb0rG` should be replaced with the name of the desired avd.

After that,  we run adb as root and remount it because it is by default mounted as `read-only` even if `-writable-system` is used.

```sh
adb root
adb remount
adb -s emulator-5554 shell
```

Finally, inside the device , mount the `/system` as read-write.

```sh
mount -o rw,remount /system
mount -o rw,remount /
```

# Setting up the gdbserver

Verify the architecture of your connected device with `uname -m` inside the adb shell.

Navigate to the `ndk` folder which should ideally be located in the `Sdk` folder itself. Once there , you will find a `prebuilt` folder in which we find `gdbserver` for various architectures.

Since I'm running the emulator on x86 , this is the path to gdbserver in my machine.

```sh
~/Android/Sdk/ndk/22.1.7171670/prebuilt/android-x86_64/gdbserver
```

Once here, we push `gdbserver` into our device with `adb push gdbserver /system/bin`.

Now that we have pushed `gdbserver` , we can easily attach to any process by it's process id. We get the `pid` of a process with `ps aux | grep <process_name>`.

```sh
gdbserver :8888 --attach 2741
```

Replace `2741` with the `pid` of the process you wish to debug.

After that , we port forward from adb shell to our host machine so that we can debug from the comforts of our local machine.

```
adb forward tcp:8888 tcp:8888
```

Now, all that is left is to fire up gdb , and run `target remote :8888`.

## Conclusion

That's all there is to setup gdb to debug native android applications.
