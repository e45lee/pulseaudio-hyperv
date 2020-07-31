# PulseAudio for Hyper-V Sockets

## About
This repository hosts a patchset that enables support for Hyper-V sockets on Windows for PulseAudio 13+.
Use this for enabling sound support on:
- Full Linux virtual machines in Hyper-V.
- Windows Subsystem for Linux 2 instances.

## Compilation
PulseAudio does not compile nicely in MSYS2, due to path translation issues.  It is faster and easier to compile
PulseAudio on Linux  using a MinGW cross compiler.

The build workflow in this repository uses a OpenSUSE Docker image for the cross-compilation.
See https://github.com/e45lee/pulseaudio-hyperv/blob/hyperv-sockets/.github/workflows/c-cpp.yml for build instructions.
The commands should be portable to your system of choice (or you could run the commands locally inside
your own OpenSUSE Docker image).

Builds are available through the artifacts published in this repository.

## Usage

### Windows (Host)
Start PulseAudio with:
```.\pulseaudio.exe --exit-idle-time=-1 -L "module-native-protocol-hyperv"```
This starts PulseAudio with the Hyper-V socket server, and keeps it alive, as there is no daemon to automatically
restart PulseAudio when needed.  By default this binds PulseAudio against port 4713 in AF_VSOCK.
To set the port, change the port argument, i.e `-L "module-native-protcol-hyperv port=4713"`.

By default, PulseAudio accepts connections from all Hyper-V instances _except_ any running WSL2 instance.
This is due to differences between a full Hyper-V instance and the lightweight WSL2 instance.

When using PulseAudio with a WSL2 instance, use:
```.\pulseaudio.exe --exit-idle-time=-1 -L "module-native-protocol-hyperv auto_wsl2=true"```
This explicitly exclusively binds the PulseAudio instance to the running WSL2 instance.
If you need to bind to both a WSL2 instance and a regular Hyper-V instance, load the Hyper-V native protocol module
twice: once for the WSL2 instance, once for the other Hyper-V instances.  Note that you will need to use
different port numbers for the two instances.

This repository also provides a helper script, `start-pulseaudio.vbs`, which wraps `pulseaudio.exe` and runs
it in the background, in a hidden window.  `start-pulseaudio.vbs` takes the same arguments as `pulseaudio.exe`.

### Linux (VM)
In principle one can add support in PulseAudio for AF_VSOCK sockets; however, this requires that local
modifications need to be made against the installed PulseAudio client libraries, which is inconvenient.

We get around this by using socat to proxy connections to the Hyper-V socket via a Unix domain socket.
Run the following to proxy the Unix domain socket .pulse.sock to AF_VSOCK port 4713.  Note that
the bytestring paramter follows the layout of `struct sockaddr_vm`  (and hence, to modify the port,
modify the four bytes in the example -- `x69x12x00x00` -- to the appropriate host-order encoding
of the desired port number).
```socat UNIX-LISTEN:.pulse.sock,fork SOCKET-CONNECT:40:0:x00x00x69x12x00x00x02x00x00x00x00x00x00x00```

Then export the following configuration variables:
```
export PULSE_COOKIE="$(wslpath $(cmd.exe /C "echo %USERPROFILE%") | tr -d '\r')/.config/pulse/cookie"
export PULSE_SERVER="unix:$HOME/.pulse.sock"
```

Finally, you may wish to fill in `$HOME/.asoundrc` with the following so that ALSA applications use PulseAudio.
```
pcm.pulse {
    type pulse
}

ctl.pulse {
    type pulse
}

pcm.!default {
    type pulse
}
ctl.!default {
    type pulse
}
```

## Credits
https://github.com/Biswa96/wslbridge2 for the code necessary to bind a Hyper-V socket against the WSL2 VM.
https://github.com/Martin1994/pulseaudio as a reference for WSL1 AF_UNIX sockets.
