const EventEmitter = require('events');
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');
const assert = require('assert');
const Mutex = require('await-semaphore').Mutex;

// RM Devices (without RF support)
const rmDeviceTypes = {};
rmDeviceTypes[0x2737] = "Broadlink RM3 Mini";
rmDeviceTypes[0x6507] = "Broadlink RM3 Mini";
rmDeviceTypes[0x27c7] = 'Broadlink RM3 Mini A';
rmDeviceTypes[0x27c2] = "Broadlink RM3 Mini B";
rmDeviceTypes[0x6508] = "Broadlink RM3 Mini D";
rmDeviceTypes[0x27de] = "Broadlink RM3 Mini C";
rmDeviceTypes[0x5f36] = "Broadlink RM3 Mini B";
rmDeviceTypes[0x27d3] = "Broadlink RM3 Mini KR";
rmDeviceTypes[0x273d] = 'Broadlink RM Pro Phicomm';
rmDeviceTypes[0x2712] = 'Broadlink RM2';
rmDeviceTypes[0x2783] = 'Broadlink RM2 Home Plus';
rmDeviceTypes[0x277c] = 'Broadlink RM2 Home Plus GDT';
rmDeviceTypes[0x278f] = 'Broadlink RM Mini Shate';
rmDeviceTypes[0x2221] = 'Manual RM Device';

// RM Devices (with RF support)
const rmPlusDeviceTypes = {};
rmPlusDeviceTypes[0x272a] = 'Broadlink RM2 Pro Plus';
rmPlusDeviceTypes[0x2787] = 'Broadlink RM2 Pro Plus v2';
rmPlusDeviceTypes[0x278b] = 'Broadlink RM2 Pro Plus BL';
rmPlusDeviceTypes[0x2797] = 'Broadlink RM2 Pro Plus HYC';
rmPlusDeviceTypes[0x27a1] = 'Broadlink RM2 Pro Plus R1';
rmPlusDeviceTypes[0x27a6] = 'Broadlink RM2 Pro PP';
rmPlusDeviceTypes[0x279d] = 'Broadlink RM3 Pro Plus';
rmPlusDeviceTypes[0x27a9] = 'Broadlink RM3 Pro Plus v2'; // (model RM 3422)
rmPlusDeviceTypes[0x27c3] = 'Broadlink RM3 Pro';
rmPlusDeviceTypes[0x2223] = 'Manual RM Pro Device';

// RM4 Devices (without RF support)
const rm4DeviceTypes = {};
rm4DeviceTypes[0x51da] = "Broadlink RM4 Mini";
rm4DeviceTypes[0x610e] = "Broadlink RM4 Mini";
rm4DeviceTypes[0x62bc] = "Broadlink RM4 Mini";
rm4DeviceTypes[0x653a] = "Broadlink RM4 Mini";
rm4DeviceTypes[0x6070] = "Broadlink RM4 Mini C";
rm4DeviceTypes[0x62be] = "Broadlink RM4 Mini C";
rm4DeviceTypes[0x610f] = "Broadlink RM4 Mini C";
rm4DeviceTypes[0x6539] = "Broadlink RM4 Mini C";
rm4DeviceTypes[0x520d] = "Broadlink RM4 Mini C";
rm4DeviceTypes[0x648d] = "Broadlink RM4 Mini S";
rm4DeviceTypes[0x5216] = "Broadlink RM4 Mini";
rm4DeviceTypes[0x520c] = "Broadlink RM4 Mini";
rm4DeviceTypes[0x2225] = 'Manual RM4 Device';

// RM4 Devices (with RF support)
const rm4PlusDeviceTypes = {};
rm4PlusDeviceTypes[0x5213] = "Broadlink RM4 Pro";
rm4PlusDeviceTypes[0x6026] = "Broadlink RM4 Pro";
rm4PlusDeviceTypes[0x61a2] = "Broadlink RM4 Pro";
rm4PlusDeviceTypes[0x649b] = "Broadlink RM4 Pro";
rm4PlusDeviceTypes[0x653c] = "Broadlink RM4 Pro";
rm4PlusDeviceTypes[0x520b] = "Broadlink RM4 Pro";
rm4PlusDeviceTypes[0x6184] = "Broadlink RM4C Pro";
rm4PlusDeviceTypes[0x2227] = 'Manual RM4 Pro Device';

// Known Unsupported Devices
const unsupportedDeviceTypes = {};
unsupportedDeviceTypes[0] = 'Broadlink SP1';
unsupportedDeviceTypes[0x2711] = 'Broadlink SP2';
unsupportedDeviceTypes[0x2719] = 'Honeywell SP2';
unsupportedDeviceTypes[0x7919] = 'Honeywell SP2';
unsupportedDeviceTypes[0x271a] = 'Honeywell SP2';
unsupportedDeviceTypes[0x791a] = 'Honeywell SP2';
unsupportedDeviceTypes[0x2733] = 'OEM Branded SP Mini';
unsupportedDeviceTypes[0x273e] = 'OEM Branded SP Mini';
unsupportedDeviceTypes[0x2720] = 'Broadlink SP Mini';
unsupportedDeviceTypes[0x7d07] = 'Broadlink SP Mini';
unsupportedDeviceTypes[0x753e] = 'Broadlink SP 3';
unsupportedDeviceTypes[0x2728] = 'Broadlink SPMini 2';
unsupportedDeviceTypes[0x2736] = 'Broadlink SPMini Plus';
unsupportedDeviceTypes[0x2714] = 'Broadlink A1';
unsupportedDeviceTypes[0x4EB5] = 'Broadlink MP1';
unsupportedDeviceTypes[0x2722] = 'Broadlink S1 (SmartOne Alarm Kit)';
unsupportedDeviceTypes[0x4E4D] = 'Dooya DT360E (DOOYA_CURTAIN_V2) or Hysen Heating Controller';
unsupportedDeviceTypes[0x4ead] = 'Dooya DT360E (DOOYA_CURTAIN_V2) or Hysen Heating Controller';
unsupportedDeviceTypes[0x947a] = 'BroadLink Outlet';

const models = {};

class Broadlink extends EventEmitter {

  constructor(log = undefined, debug = undefined) {
    super();
    
    this.devices = {};
    this.sockets = [];
    
    if (log) {
      this.log = log;
    }
    if (debug) {
      this.debug = debug;
    }
  }

  discover({local_ip_address = undefined,
	    discover_ip_address = '255.255.255.255',
	    discover_ip_port = 80} = {}) {

    if (this.debug === false) {	// Wasting codes, but compatibility for conventional.
      this.debug = undefined;
    } else if (this.debug === true) {
      this.debug = 0;
    }
    
    // Close existing sockets
    this.sockets.forEach((socket) => {
      socket.close();
    })

    this.sockets = [];

    // Open a UDP socket on each network interface/IP address
    const ipAddresses = local_ip_address ?? this.getIPAddresses();

    ipAddresses.forEach((ipAddress) => {
      const socket = dgram.createSocket({ type:'udp4', reuseAddr:true });
      this.sockets.push(socket)

      socket.on('listening', this.onListening.bind(this, socket, ipAddress, discover_ip_address, discover_ip_port));
      socket.on('message', this.onMessage.bind(this));

      socket.bind(0, ipAddress);	// triggers onListening()
    });
  }

  getIPAddresses() {
    const interfaces = os.networkInterfaces();
    const ipAddresses = [];

    Object.keys(interfaces).forEach((interfaceID) => {
      const currentInterface = interfaces[interfaceID];

      currentInterface.forEach((address) => {
        if ((address.family === 'IPv4' || address.family === 4) && !address.internal) {
          ipAddresses.push(address.address);
        }
      })
    });

    return ipAddresses;
  }

  onListening (socket, ipAddress, discover_ip_address, discover_ip_port) {
    const { debug, log } = this;

    // Broadcase a multicast UDP message to let Broadlink devices know we're listening
    socket.setBroadcast(true);

    const port = socket.address().port;
    this.logs.trace(`Listening for Broadlink devices on ${ipAddress}:${port} (UDP)`);

    const now = new Date();
    const starttime = now.getTime();

    const timezone = now.getTimezoneOffset() / -60;
    const packet = Buffer.alloc(0x30, 0);
    const year = now.getFullYear();

    packet.writeInt32LE(timezone, 0x08);
    packet.writeInt16LE(year, 0x0c);
    packet[0x0e] = now.getMinutes();
    packet[0x0f] = now.getHours();
    packet[0x10] = year % 100;
    packet[0x11] = now.getDay();
    packet[0x12] = now.getDate();
    packet[0x13] = now.getMonth() + 1;
    packet.set(ipAddress.split('.').reverse(), 0x18);
    packet.writeUint16LE(port, 0x1c);
    packet[0x26] = 0x06;

    let checksum = packet.reduce((x, y) => {return x + y}, 0xbeaf) & 0xffff;
    packet.writeUint16LE(checksum, 0x20);

    this.logs.trace(`Sending descover: ${packet.toString('hex')}`);
    socket.sendto(packet, 0, packet.length, discover_ip_port, discover_ip_address);
  }

  onMessage (message, host) {
    const { debug, log } = this;
    // Broadlink device has responded
    const macAddress = Buffer.alloc(6, 0);

    message.copy(macAddress, 0x00, 0x3A);
    macAddress.reverse();

    // Ignore if we already know about this device
    const key = macAddress.toString('hex');
    if (this.devices[key]) return;

    const deviceType = message.readUint16LE(0x34);
    const isLocked  = message[0x7F] ? true : false;
    if (debug < 1 && log) {
      const name = message.subarray(0x40, 0x40 + message.subarray(0x40).indexOf(0x0)).toString('utf8');
      const ip = [...message.subarray(0x36, 0x3A)].reverse();
      
      this.logs.trace(`Found Broadlink device. address:${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}, type:0x${deviceType.toString(16)}, locked:${isLocked}, name:${name}`);
    }
    if (isLocked) {
      this.devices[key] = 'Not Supported';
      // this.logs.info(`Discovered \x1b[33mLocked\x1b[0m Broadlink device at ${host?.address} (${key.match(/[\s\S]{1,2}/g).join(':')}) with type 0x${deviceType.toString(16)}. Unlock to control.`);
      this.logs.warn(`Skipping \x1b[33mLocked\x1b[0m device ${key} with type 0x${deviceType.toString(16)}. Unlock the device to control.`);
      return;
    }

    // Create a Device instance
    this.addDevice(host, macAddress, deviceType);
  }

  async addDevice (host, macAddress, deviceType) {
    const { log, debug } = this;

    if (this.devices[macAddress.toString('hex')]) return;

    const isHostObjectValid = (
      typeof host === 'object' &&
      (host.port || host.port === 0) &&
      host.address
    );

    assert(isHostObjectValid, `createDevice: host should be an object e.g. { address: '192.168.1.32', port: 80 }`);
    assert(macAddress, `createDevice: A unique macAddress should be provided`);
    assert(deviceType, `createDevice: A deviceType from the rmDeviceTypes, rm4DeviceTypes, rm4PlusDeviceTypes, or rmPlusDeviceTypes list should be provided`);

    // Mark is at not supported by default so we don't try to
    // create this device again.
    this.devices[macAddress.toString('hex')] = 'Not Supported';

    // Ignore devices that don't support infrared or RF.
    if (unsupportedDeviceTypes[deviceType]) return null;
    if (deviceType >= 0x7530 && deviceType <= 0x7918) return null; // OEM branded SPMini2

    // If we don't know anything about the device we ask the user to provide details so that
    // we can handle it correctly.
    const isKnownDevice = models[deviceType];

    if (!isKnownDevice) {
      this.logs.log(`\n\x1b[35m[Info]\x1b[0m We've discovered an unknown Broadlink device of type code "${deviceType.toString(16)}". The device is connected to your network with the IP address "${host.address}".\n`);

      return null;
    }

    // The Broadlink device is something we can use.
    const device = new models[deviceType].class(log, host, macAddress, deviceType, debug)
    // device.log = log;
    // device.debug = debug;
    // device.actives = new Map();

    this.devices[macAddress.toString('hex')] = device;

    // Authenticate the device and let others know when it's ready.
    device.on('deviceReady', async () => {
      device.name = (await device.getDeviceName(this.debug))?.name;	// bad practice?
      this.emit('deviceReady', device);
    });

    for (let i = 0; i < 3; i++) {
      if (await device.authenticate()) {
	return;
      }
      this.logs.warn(`Retrying to authenticate Broadlink device (attempt ${i+1}). device:${macAddress.toString('hex')}`);
    }
    this.logs.error(`Failed to authenticate Broadlink device despite three times attempt. device:${macAddress.toString('hex')}`);
  }

  logs = {
    log: (format, ...args) => {
      this.log(format, ...args);
    },
    trace: (format, ...args) => {
      if (this.debug < 1) {
	format = "%s " + format;
	this.log(format, `\x1b[90m[TRACE]`, ...args, '\x1b[0m');
      }
    },
    debug: (format, ...args) => {
      if (this.debug < 2) {
	format = "%s " + format;
	this.log(format, `\x1b[90m[DEBUG]`, ...args, '\x1b[0m');
      }
    },
    info: (format, ...args) => {
      if (this.debug < 3) {
	format = "%s " + format;
	this.log(format, `\x1b[35m[INFO]\x1b[0m`, ...args);
      }
    },
    warn: (format, ...args) => {
      if (this.debug < 4) {
	format = "%s " + format;
	this.log(format, `\x1b[33m[WARN]\x1b[0m`, ...args);
      }
    },
    error: (format, ...args) => {
      // if (this.debug < 5) {
	format = "%s " + format;
      this.log(format, `\x1b[31m[ERROR]\x1b[0m`, ...args);
      // }
    }
  }

  close = () => {
    this.sockets.forEach((socket) => {
      socket.close();
    })
    this.sockets = [];

    Object.keys(this.devices).forEach((device) => {
      this.devices[device]?.socket.close();
    })
    this.devices = [];
  }
}

class Device {

  constructor (log, host, macAddress, deviceType, debug) {
    if (typeof macAddress === 'string') {	// 'hosts' interface
      macAddress = Buffer.from(macAddress.toLowerCase().replace(/:/g, ''), "hex");
    }

    this.host = host;
    this.mac = macAddress;
    this.emitter = new EventEmitter();
    // this.log = console.log;
    this.log = log;
    this.debug = debug;
    this.type = deviceType;
    this.model = models[deviceType].model;
    this.actives = new Map();
    this.que = new Mutex();

    this.on = this.emitter.on;
    this.once = this.emitter.once;
    this.emit = this.emitter.emit;
    this.removeListener = this.emitter.removeListener;
    this.removeAllListeners = this.emitter.removeAllListeners

    this.count = Math.random() & 0xffff;
    this.key = new Buffer.from([0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]);
    this.iv = new Buffer.from([0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]);
    this.id = new Buffer.from([0, 0, 0, 0]);

    this.setupSocket();
  }

  // Create a UDP socket to receive messages from the broadlink device.
  setupSocket() {
    const { log } = this;
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.socket = socket;

    socket.on('message', (response) => {
      if(response.length < 0x39) {
	this.logs.error(this.debug, 'Incomplete response: ', response.toString('hex'), 'length: ', response.length);
	return;
      }
      const encryptedPayload = Buffer.alloc(response.length - 0x38, 0);
      response.copy(encryptedPayload, 0, 0x38);

      const command = response[0x26];
      const err = response.readUint16LE(0x22);
      const ix = response.readUint16LE(0x28);

      const decipher = crypto.createDecipheriv('aes-128-cbc', this.key, this.iv);
      decipher.setAutoPadding(false);

      let payload = decipher.update(encryptedPayload);

      const p2 = decipher.final();
      if (p2) payload = Buffer.concat([payload, p2]);

      if (!payload) {
	this.logs.error(this.debug, 'Empty payload:', response.toString('hex'), 'command:', '0x'+response[0x26].toString(16), 'error:', '0x'+err.toString(16));
	return false;
      }

      if (this.actives.has(ix)) {
	const {command, debug} = this.actives.get(ix);
	this.actives.delete(ix);
	if (response) this.logs.trace(debug, `respond packet: ${response.subarray(0, 0x39).toString('hex')} ${payload.toString('hex')} ix:${ix}`);
	this.emit(command, err, ix, payload);
      } else if (command == 0x72) {
        this.logs.debug(this.debug, `command Acknowledged. source:${ix} payload:${payload.toString('hex')}`);
      } else {
        this.logs.error(this.debug, `unhandled Command 0x${command.toString(16)} in a response of Broadlink device. payload:${payload.toString('hex')} ix:${ix}`);
      }
    });

    socket.bind();
  }

  async authenticate() {
    const { log, debug } = this;
    const payload = Buffer.alloc(0x50, 0);

    payload[0x04] = 0x31;
    payload[0x05] = 0x31;
    payload[0x06] = 0x31;
    payload[0x07] = 0x31;
    payload[0x08] = 0x31;
    payload[0x09] = 0x31;
    payload[0x0a] = 0x31;
    payload[0x0b] = 0x31;
    payload[0x0c] = 0x31;
    payload[0x0d] = 0x31;
    payload[0x0e] = 0x31;
    payload[0x0f] = 0x31;
    payload[0x10] = 0x31;
    payload[0x11] = 0x31;
    payload[0x12] = 0x31;
    payload[0x1e] = 0x01;
    payload[0x2d] = 0x01;
    payload[0x30] = 'T'.charCodeAt(0);
    payload[0x31] = 'e'.charCodeAt(0);
    payload[0x32] = 's'.charCodeAt(0);
    payload[0x33] = 't'.charCodeAt(0);
    payload[0x34] = ' '.charCodeAt(0);
    payload[0x35] = ' '.charCodeAt(0);
    payload[0x36] = '1'.charCodeAt(0);

    return new Promise((resolve, reject) => {
      const time0 = new Date();
      this.sendPacket(0x65, payload, this.debug, async (senderr, ix0) => {
	const commandx = `auth${ix0}`;
	this.actives.set(ix0, {command: commandx, debug: debug});
	if (senderr) {
	  return reject(`${senderr}`);	// sendPacket error
	}
	const timeout = setTimeout(() => {
	  this.removeAllListeners(commandx);
	  this.actives.delete(ix0);
	  reject(`Timed out of 5 second(s) in response. source:${ix0}`);
	}, 5*1000);
	const listener = (status, ix, response) => {
	  clearTimeout(timeout);
	  const dt = (new Date() - time0) / 1000;
	  if (status) {
	    reject(`Error response in ${dt.toFixed(2)} sec. source:${ix0}`);
	  } else {
            this.key = Buffer.alloc(0x10, 0);
            response.copy(this.key, 0, 0x04, 0x14);
	    
            this.id = Buffer.alloc(0x04, 0);
            response.copy(this.id, 0, 0x00, 0x04);
	    
	    this.logs.trace(debug, `successfully authenticated in ${dt.toFixed(2)} sec. source:${ix0}`);
	    
            this.emit('deviceReady');
	    resolve(true);
	  }
	}
	await this.once(commandx, listener);
      });
    }).catch((e) => {
      this.logs.debug(debug, `failed to authenticate Broadlink device. ${e}`);
      return false;
    });
  }

  async sendPacket (command, payload, debug = undefined, callback = null) {
    const { log, socket } = this;
    //debug = this.debug;
    this.count = (this.count + 1) & 0xffff;
    const ix = this.count;	// save the value before overridden.

    let packet = Buffer.alloc(0x38, 0);

    packet.set([0x5a, 0xa5, 0xaa, 0x55, 0x5a, 0xa5, 0xaa, 0x55], 0x0),
    packet.writeUint16LE(this.type, 0x24);
    packet.writeUint16LE(command, 0x26);
    packet.writeUint16LE(this.count, 0x28);
    packet.set([...this.mac].reverse(), 0x2a);
    packet.set(this.id, 0x30);

    if (payload){
      this.logs.trace(debug, `sending command 0x${command.toString(16)} with payload ${payload.toString('hex')}`);
      const padPayload = Buffer.alloc(16 - payload.length % 16, 0)
      payload = Buffer.concat([payload, padPayload]);
    }

    let checksum = payload.reduce((x, y) => {return x + y}, 0xbeaf) & 0xffff;
    packet.writeUint16LE(checksum, 0x34);

    const cipher = crypto.createCipheriv('aes-128-cbc', this.key, this.iv);
    payload = cipher.update(payload);

    packet = Buffer.concat([packet, payload]);

    checksum = packet.reduce((x, y) => {return x + y}, 0xbeaf) & 0xffff;
    packet.writeUint16LE(checksum, 0x20);

    this.logs.trace(`sending packet ${packet.subarray(0, 0x39).toString('hex')} ${packet.subarray(0x39).toString('hex')} ix:${ix}`);

    socket.send(packet, 0, packet.length, this.host.port, this.host.address, (err) => {
      if (err) this.logs.error(debug, 'send packet error', err);
      callback?.(err, ix);
    })
  }	     

  // Externally Accessed Methods

  async sendPacketSync(command, packet, debug = undefined) {
    return await this.que.use(async () => {
      const { log } = this;
      // const x = new Error('Trace:');
      return await new Promise((resolve, reject) => {
	const time0 = new Date();
	this.sendPacket(0x6a, packet, debug, async (senderr, ix0) => {
	  const commandx = `${command}${ix0}`;
	  this.actives.set(ix0, {command: commandx, debug: debug});
	  if (senderr) {
	    return reject(new Error(`${senderr}`));	// sendPacket error
	  }
	  const timeout = setTimeout(() => {
	    this.removeAllListeners(commandx);
	    this.actives.delete(ix0);
	    reject(new Error(`Timed out of 5 second(s) in response to ${command}. source:${ix0}`));
	  }, 5*1000);
	  const listener = (status, ix, payload) => {
	    const dt = (new Date() - time0) / 1000;
	    clearTimeout(timeout);
	    if (status) {
	      this.logs.debug(debug, `error response of ${command} in ${dt.toFixed(2)} sec. source:${ix0}`);
	      resolve(null);
	    } else {
	      this.logs.trace(debug, `succeed response of ${command} in ${dt.toFixed(2)} sec. source:${ix0}`);
	      resolve(payload);
	    }
	  }
	  await this.once(commandx, listener);
	});
      })
      /*.catch((e) => {
	// if (debug) log(`\x1b[31m[ERROR]\x1b[0m Failed to send/receive packet. ${e} device:${this.mac.toString('hex')} ${x.stack.substring(7)}`);
	this.logs.error(debug, `failed to send/receive packet. ${e}`);
      })*/
    })
  }
  
  ping = async (debug = undefined) => {await this.que.use(async () => {
    const packet = Buffer.alloc(0x30, 0);
    packet[0x26] = 0x1;
    this.logs.trace(debug, 'sending keepalive to', this.host.address,':',this.host.port);
    this.socket.send(packet, 0, packet.length, this.host.port, this.host.address, (err) => {
      if (err) this.logs.error(debug, '\x1b[33m[DEBUG]\x1b[0m send keepalive packet error', err)
    })
  })}

  pauseWhile = async (callback, debug = undefined) => {await this.que.use(async () => {
    this.logs.trace(debug, `pausing while the requested operation.`);
    callback();
  })}

  getFWversion = async (debug = undefined) => {
    try { 
      const packet = Buffer.from([0x68]);
      const payload = await this.sendPacketSync('getFWversion', packet, debug);
      return payload ? payload.readUint16LE(0x04) : undefined;
    } catch (e) {
      this.logs.warn(debug, `Failed to get firmware version. ${e}`)
      return undefined;
    }
  }

  getDeviceName = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x1, 0x00, 0x00, 0x00]);
      const payload = await this._send('getDeviceName', packet, debug)
      if (payload) {
	const name = payload.subarray(0x48, 0x48 + payload.subarray(0x48).indexOf(0x0)).toString('utf8');
	const lock = payload[0x87] ? true : false;
	return {name, lock};
      }
      return undefined;
    } catch (e) {
      this.logs.warn(debug, `failed to get device name and lock status from Broadlink device. ${e}`)
      return undefined;
    }
  }

  _sendRM = async (command, data, debug) => {
    try {
      const payload = await this.sendPacketSync(command, data, debug);
      return payload ? payload.subarray(4) : null;
    } catch (e) {
      throw e;
    }
  }

  _sendRM4 = async (command, data, debug) => {
    try {
      const header = Buffer.alloc(2, 0);
      header.writeUint16LE(data.length);
      const packet = Buffer.concat([header, data]);
      const payload = await this.sendPacketSync(command, packet, debug);
      if (payload) {
	const l = payload.readUint16LE(0);
	return payload.subarray(6, l + 2);
      } else {
	return null;
      }
    } catch (e) {
      throw e;
    }
  }

  logs = {
    log: (format, ...args) => {
      this.log && this.log(format, ...args);
    },
    trace: (debug, format, ...args) => {
      if (debug < 1) {
	format = "%s " + format;
	this.log && this.log(format, `\x1b[90m[TRACE] ${this.mac ? this.mac.toString('hex').match(/../g).join(':') : ""}`, ...args, '\x1b[0m');
      }
    },
    debug: (debug, format, ...args) => {
      if (debug < 2) {
	format = "%s " + format;
	this.log && this.log(format, `\x1b[90m[DEBUG] ${this.mac ? this.mac.toString('hex').match(/../g).join(':') : ""}`, ...args, '\x1b[0m');
      }
    },
    info: (debug, format, ...args) => {
      if (debug < 3) {
	format = "%s " + format;
	this.log && this.log(format, `\x1b[35m[INFO]\x1b[0m ${this.mac ? this.mac.toString('hex').match(/../g).join(':') : ""}`, ...args);
      }
    },
    warn: (debug, format, ...args) => {
      if (debug < 4) {
	format = "%s " + format;
	this.log && this.log(format, `\x1b[33m[WARN]\x1b[0m ${this.mac ? this.mac.toString('hex').match(/../g).join(':') : ""}`, ...args);
      }
    },
    error: (debug, format, ...args) => {
      // if (debug < 5) {
	format = "%s " + format;
      this.log && this.log(format, `\x1b[31m[ERROR]\x1b[0m ${this.mac ? this.mac.toString('hex').match(/../g).join(':') : ""}`, ...args);
      // }
    }
  }
}

class rmmini extends Device {
  constructor(log, host, macAddress, deviceType, debug) {
    super(log, host, macAddress, deviceType, debug);
  }

  _send = this._sendRM;

  sendData = async (data, debug = undefined) => {
    try {
      let packet = new Buffer.from([0x02, 0x00, 0x00, 0x00]);
      packet = Buffer.concat([packet, data]);
      const payload = await this._send('sendData', packet, debug);
      if (!payload) {
	this.logs.error(debug, `failed to send HEX code. Error: null payload response.`);
      }
      return 0;
    } catch (e) {
      this.logs.error(debug, `failed to send HEX code. ${e}`)
      return -1;
    }
  }

  enterLearning = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x03, 0x00, 0x00, 0x00]);
      await this._send('enterLearning', packet, debug);
    } catch (e) {
      this.logs.error(debug, `failed to enter learning mode. ${e}`)
    }
  }

  cancelLearn = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x1e, 0x00, 0x00, 0x00]);
      await this._send('cancelLearning', packet, debug);
    } catch (e) {
      this.logs.error(debug, `failed to cancel learning mode. ${e}`)
    }
  }
  cancelLearning = this.cancelLearn;
  
  checkData = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x04, 0x00, 0x00, 0x00]);
      const payload = await this._send('checkData', packet, debug)
      if (payload) {
	this.emit('rawData', payload);
	return payload;
      }
      return null;
    } catch (e) {
      this.logs.error(debug, `failed to capture IR/RF HEX code. ${e}`)
      return null;
    }
  }
}

class rmpro extends rmmini {
  constructor(log, host, macAddress, deviceType, debug) {
    super(log, host, macAddress, deviceType, debug);
    
    this.logs.log(`\x1b[35m[INFO]\x1b[0m Adding RF Support to device ${macAddress.toString('hex')} with type 0x${deviceType.toString(16)}`);
  }

  _send = this._sendRM;

  checkTemperature = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x1, 0x00, 0x00, 0x00]);
      const payload = await this._send('checkTemperature', packet, debug)
      if (payload) {
	const temperture = payload[0x0] + payload[0x1] / 10.0;
	this.emit('temperature', temperture);
	return temperture;
      }
      return undefined;
    } catch (e) {
      this.logs.warn(debug, `failed to get temperature from Broadlink device. ${e}`)
      return undefined;
    }
  }
  checkSensors = this.checkTemperature;
  checkHumidity = this.checkTemperature;
  
  enterRFSweep = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x19, 0x00, 0x00, 0x00]);
      await this._send('enterRFSweep', packet, debug);
    } catch (e) {
      this.logs.error(debug, `failed to enter RF frequency sweeping mode. ${e}`)
    }
  }
  sweepFrequency = this.enterRFSweep;

  checkRFData = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x1a, 0x00, 0x00, 0x00]);
      const payload = await this._send('checkFrequency', packet, debug);
      if (payload) {
	if (payload[0]) {
	  this.emit('rawRFData', payload);
	}
	return {
	  locked: payload[0],
	  frequency: payload.readUint32LE(1)/1000
	}
      }
      return null;
    } catch (e) {
      this.logs.error(debug, `failed to find RF frequency. ${e}`)
      return null;
    }
  }
  checkFrequency = this.checkRFData;

  checkRFData2 = async (frequency, debug = undefined) => {
    try {
      let packet = new Buffer.from([0x1b, 0x00, 0x00, 0x00]);
      if (frequency) {
	const data = Buffer.alloc(4, 0);
	data.writeUint32LE(Math.round(frequency * 1000));
	packet = Buffer.concat([packet, data]);
      }
      const payload = await this._send('checkRFData2', packet, debug);
      if (payload) {
	this.emit('rawRFData2', payload);
      }
    } catch (e) {
      this.logs.error(debug, `failed to enter RF capturing mode. ${e}`)
    }
  }
  findRFPacket = this.checkRFData2;
}

class rm4mini extends rmmini {
    constructor(log, host, macAddress, deviceType, debug) {
    super(log, host, macAddress, deviceType, debug);
  }

  _send = this._sendRM4;

  checkSensors = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x24, 0x00, 0x00, 0x00]);
      const payload = await this._send('checkSensors', packet, debug)
      if (payload) {
	const temperature = payload[0x0] + payload[0x1] / 100.0;
	const humidity = payload[0x2] + payload[0x3] / 100.0;
	this.emit('temperature',temperature, humidity);
	return {
          "temperature": temperature,
          "humidity": humidity
	}
      }
      return undefined;
    } catch (e) {
      this.logs.warn(debug, `failed to get temperature/humidity from Broadlink device. ${e}`)
      return undefined;
    }
  }
  checkTemperature = async (debug = undefined) => {
    return await this.checkSensors(debug)?.temperature;
  }
  checkHumidity =  async (debug = undefined) => {
    return await this.checkSensors(debug)?.humidity;
  }
}

class rm4pro extends rmpro {
  constructor(log, host, macAddress, deviceType, debug) {
    super(log, host, macAddress, deviceType, debug);
  }

  _send = this._sendRM4;

  checkSensors = async (debug = undefined) => {
    try {
      const packet = new Buffer.from([0x24, 0x00, 0x00, 0x00]);
      const payload = await this._send('checkSensors', packet, debug)
      if (payload) {
	const temperature = payload[0x0] + payload[0x1] / 100.0;
	const humidity = payload[0x2] + payload[0x3] / 100.0;
	this.emit('temperature',temperature, humidity);
	return {
          "temperature": temperature,
          "humidity": humidity
	}
      }
      return undefined;
    } catch (e) {
      this.logs.warn(debug, `failed to get temperature/humidity from Broadlink device. ${e}`)
      return undefined;
    }
  }
  checkTemperature = async (debug = undefined) => {
    return await this.checkSensors(debug)?.temperature;
  }
  checkHumidity =  async (debug = undefined) => {
    return await this.checkSensors(debug)?.humidity;
  }

  cancelSweepFrequency = this.cancelLearn;
}

Object.keys(rmDeviceTypes).forEach((x) => {
  models[x] = {
    model: rmDeviceTypes[x],
    class: rmmini
  }
})
Object.keys(rmPlusDeviceTypes).forEach((x) => {
  models[x] = {
    model: rmPlusDeviceTypes[x],
    class: rmpro
  }
})
Object.keys(rm4DeviceTypes).forEach((x) => {
  models[x] = {
    model: rm4DeviceTypes[x],
    class: rm4mini
  }
})
Object.keys(rm4PlusDeviceTypes).forEach((x) => {
  models[x] = {
    model: rm4PlusDeviceTypes[x],
    class: rm4pro
  }
})
models[0x5f36].class = rm4mini;
models[0x6508].class = rm4mini;

module.exports = Broadlink;
