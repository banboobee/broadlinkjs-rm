# Broadlink RM

## Introduction
This module allows you to control the IR and RF interfaces within Broadlink RM devices. Enhanced the initial work with duplicating the internal structures of python-broadlink to confirm the control results.

## Events

| event | description |
| --- | --- |
| `deviceReady` | Emitted with the `Device` once it has authenticated and is ready to accept commands. Also emitted again after a device re-authenticates. |
| `deviceMoved` | Emitted with the `Device` when a known device answers discovery from a different address. `device.host.address` has already been updated and the device is re-authenticating. Useful for consumers that index devices by address. |

## Thanks
Thanks to @lprhodes (https://github.com/lprhodes/broadlinkjs-rm/) and @momodalo (https://github.com/momodalo/broadlinkjs/) for the initial work. Also thanks to @mjg59 (https://github.com/mjg59/python-broadlink/) for the working reference.
