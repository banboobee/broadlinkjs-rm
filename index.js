const EventEmitter = require('events');
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');
const assert = require('assert');

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


class Broadlink extends EventEmitter {

  constructor() {
    super();

    this.devices = {};
    this.sockets = [];
  }

  discover() {
    // Close existing sockets
    this.sockets.forEach((socket) => {
      socket.close();
    })

    this.sockets = [];

    // Open a UDP socket on each network interface/IP address
    const ipAddresses = this.getIPAddresses();

    ipAddresses.forEach((ipAddress) => {
      const socket = dgram.createSocket({ type:'udp4', reuseAddr:true });
      this.sockets.push(socket)

      socket.on('listening', this.onListening.bind(this, socket, ipAddress));
      socket.on('message', this.onMessage.bind(this));

      socket.bind(0, ipAddress);
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

  onListening (socket, ipAddress) {
    const { debug, log } = this;

    // Broadcase a multicast UDP message to let Broadlink devices know we're listening
    socket.setBroadcast(true);

    const splitIPAddress = ipAddress.split('.');
    const port = socket.address().port;
    if (debug && log) log(`\x1b[35m[INFO]\x1b[0m Listening for Broadlink devices on ${ipAddress}:${port} (UDP)`);

    const now = new Date();
    const starttime = now.getTime();

    const timezone = now.getTimezoneOffset() / -3600;
    const packet = Buffer.alloc(0x30, 0);

    const year = now.getYear();

    if (timezone < 0) {
      packet[0x08] = 0xff + timezone - 1;
      packet[0x09] = 0xff;
      packet[0x0a] = 0xff;
      packet[0x0b] = 0xff;
    } else {
      packet[0x08] = timezone;
      packet[0x09] = 0;
      packet[0x0a] = 0;
      packet[0x0b] = 0;
    }

    packet[0x0c] = year & 0xff;
    packet[0x0d] = year >> 8;
    packet[0x0e] = now.getMinutes();
    packet[0x0f] = now.getHours();

    const subyear = year % 100;
    packet[0x10] = subyear;
    packet[0x11] = now.getDay();
    packet[0x12] = now.getDate();
    packet[0x13] = now.getMonth();
    packet[0x18] = parseInt(splitIPAddress[0]);
    packet[0x19] = parseInt(splitIPAddress[1]);
    packet[0x1a] = parseInt(splitIPAddress[2]);
    packet[0x1b] = parseInt(splitIPAddress[3]);
    packet[0x1c] = port & 0xff;
    packet[0x1d] = port >> 8;
    packet[0x26] = 6;

    let checksum = 0xbeaf;

    for (let i = 0; i < packet.length; i++) {
      checksum += packet[i];
    }

    checksum = checksum & 0xffff;
    packet[0x20] = checksum & 0xff;
    packet[0x21] = checksum >> 8;

    socket.sendto(packet, 0, packet.length, 80, '255.255.255.255');
  }

  onMessage (message, host) {
    // Broadlink device has responded
    const macAddress = Buffer.alloc(6, 0);

    message.copy(macAddress, 0x00, 0x3F);
    message.copy(macAddress, 0x01, 0x3E);
    message.copy(macAddress, 0x02, 0x3D);
    message.copy(macAddress, 0x03, 0x3C);
    message.copy(macAddress, 0x04, 0x3B);
    message.copy(macAddress, 0x05, 0x3A);

    // Ignore if we already know about this device
    const key = macAddress.toString('hex');
    if (this.devices[key]) return;

    const deviceType = message[0x34] | (message[0x35] << 8);

    // Create a Device instance
    this.addDevice(host, macAddress, deviceType);
  }

  addDevice (host, macAddress, deviceType) {
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
    const isKnownDevice = (rmDeviceTypes[deviceType] || rmPlusDeviceTypes[deviceType] || rm4DeviceTypes[deviceType]  || rm4PlusDeviceTypes[deviceType])

    if (!isKnownDevice) {
      log(`\n\x1b[35m[Info]\x1b[0m We've discovered an unknown Broadlink device. This likely won't cause any issues.\n\nPlease raise an issue in the GitHub repository (https://github.com/kiwi-cam/homebridge-broadlink-rm/issues) with details of the type of device and its device type code: "${deviceType.toString(16)}". The device is connected to your network with the IP address "${host.address}".\n`);

      return null;
    }

    // The Broadlink device is something we can use.
    const device = new Device(log, host, macAddress, deviceType)
    device.log = log;
    device.debug = debug;
    device.actives = new Map();

    this.devices[macAddress.toString('hex')] = device;

    // Authenticate the device and let others know when it's ready.
    device.on('deviceReady', () => {
      this.emit('deviceReady', device);
    });

    device.authenticate();
  }
}

class Device {

    constructor (log, host, macAddress, deviceType, port) {
    this.host = host;
    this.mac = macAddress;
    this.emitter = new EventEmitter();
    // this.log = console.log;
    this.log = log;
    this.type = deviceType;
    this.model = rmDeviceTypes[deviceType] || rmPlusDeviceTypes[deviceType] || rm4DeviceTypes[deviceType] || rm4PlusDeviceTypes[deviceType];

    //Use different headers for rm4 devices
    this.rm4Type = (rm4DeviceTypes[deviceType] || rm4PlusDeviceTypes[deviceType])
    this.request_header = this.rm4Type ? new Buffer.from([0x04, 0x00]) : new Buffer.from([]);
    this.code_sending_header = this.rm4Type ? new Buffer.from([0xda, 0x00]) : new Buffer.from([]);
    //except 5f36 and 6508 ¯\_(ツ)_/¯
    if (deviceType == 0x5f36 || deviceType == 0x6508) {
      this.code_sending_header = new Buffer.from([0xd0, 0x00]);
      this.request_header = new Buffer.from([0x04, 0x00]);
    }

    this.on = this.emitter.on;
    this.once = this.emitter.once;
    this.emit = this.emitter.emit;
    this.removeListener = this.emitter.removeListener;

    this.count = Math.random() & 0xffff;
    this.key = new Buffer.from([0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]);
    this.iv = new Buffer.from([0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]);
    this.id = new Buffer.from([0, 0, 0, 0]);

    this.setupSocket();

    // Dynamically add relevant RF methods if the device supports it
    const isRFSupported = rmPlusDeviceTypes[deviceType] || rm4PlusDeviceTypes[deviceType];
    if (isRFSupported) {
      this.log(`\x1b[35m[INFO]\x1b[0m Adding RF Support to device ${macAddress.toString('hex')} with type ${deviceType.toString(16)}`);
      this.addRFSupport();
    }
  }

  // Create a UDP socket to receive messages from the broadlink device.
  setupSocket() {
    const { log, debug } = this;
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.socket = socket;

    socket.on('message', (response) => {
      if(response.length < 0x39) {
	/* if (debug) */ log('\x1b[33m[DEBUG]\x1b[0m Incomplete response: ', response.toString('hex'), 'length: ', response.length);
	return;
      }
      const encryptedPayload = Buffer.alloc(response.length - 0x38, 0);
      response.copy(encryptedPayload, 0, 0x38);

      const command = response[0x26];
      const err = response[0x22] | (response[0x23] << 8);
      const ix = response[0x28] | (response[0x29] << 8);

      const decipher = crypto.createDecipheriv('aes-128-cbc', this.key, this.iv);
      decipher.setAutoPadding(false);

      let payload = decipher.update(encryptedPayload);

      const p2 = decipher.final();
      if (p2) payload = Buffer.concat([payload, p2]);

      if (!payload) {
	/* if (debug) */ log('\x1b[33m[DEBUG]\x1b[0m Empty payload:', response.toString('hex'), 'command:', '0x'+response[0x26].toString(16), 'error:', '0x'+err.toString(16));
	return false;
      }

      // /*if (debug && response)*/ log('\x1b[33m[DEBUG]\x1b[0m Response received: ', response.toString('hex'), 'command: ', '0x'+response[0x26].toString(16));
      if (debug && response) log('\x1b[33m[DEBUG]\x1b[0m Response received: ', response.toString('hex').substring(0, 0x38*2)+' '+payload.toString('hex'), 'command:', '0x'+command.toString(16), 'ix:', ix);

      // const command = response[0x26];
      if (command == 0xe9) {
	if (err != 0) return;
        this.key = Buffer.alloc(0x10, 0);
        payload.copy(this.key, 0, 0x04, 0x14);

        this.id = Buffer.alloc(0x04, 0);
        payload.copy(this.id, 0, 0x00, 0x04);

        this.emit('deviceReady');
      } else if (command == 0xee || command == 0xef) {
        // const payloadHex = payload.toString('hex');
        // const requestHeaderHex = this.request_header.toString('hex');

        // const indexOfHeader = payloadHex.indexOf(requestHeaderHex);

        // if (indexOfHeader > -1) {
        //   payload = payload.slice(indexOfHeader + this.request_header.length, payload.length);
        // }
	if (this.onPayloadReceivedSync(err, ix, payload)) {
	  return;
	} else {
          // this.onPayloadReceived(err, payload);	// conventional methods
          log(`\x1b[31m[ERROR]\x1b[0m Unhandled Command sequence: ${this.mac.toString('hex')}, ${command}, ${payload.toString('hex')}`);
	}
      } else if (command == 0x72) {
        log('\x1b[35m[INFO]\x1b[0m Command Acknowledged');
      } else {
        log('\x1b[33m[DEBUG]\x1b[0m Unhandled Command: ', command);
      }
    });

    socket.bind();
  }

  authenticate() {
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

    this.sendPacket(0x65, payload);
  }

  sendPacket (command, payload, debug = false, callback = null) {
    const { log, socket } = this;
    //debug = this.debug;
    this.count = (this.count + 1) & 0xffff;
    const ix = this.count;	// save the value before overridden.

    let packet = Buffer.alloc(0x38, 0);

    packet[0x00] = 0x5a;
    packet[0x01] = 0xa5;
    packet[0x02] = 0xaa;
    packet[0x03] = 0x55;
    packet[0x04] = 0x5a;
    packet[0x05] = 0xa5;
    packet[0x06] = 0xaa;
    packet[0x07] = 0x55;
    packet[0x24] = this.type & 0xff
    packet[0x25] = this.type >> 8
    packet[0x26] = command;
    packet[0x28] = this.count & 0xff;
    packet[0x29] = this.count >> 8;
    packet[0x2a] = this.mac[2]
    packet[0x2b] = this.mac[1]
    packet[0x2c] = this.mac[0]
    packet[0x2d] = this.mac[3]
    packet[0x2e] = this.mac[4]
    packet[0x2f] = this.mac[5]
    packet[0x30] = this.id[0];
    packet[0x31] = this.id[1];
    packet[0x32] = this.id[2];
    packet[0x33] = this.id[3];

    if (payload){
      if (debug) log(`\x1b[33m[DEBUG]\x1b[0m (${this.mac.toString('hex')}) Sending command:${command.toString(16)} with payload: ${payload.toString('hex')}`);
      const padPayload = Buffer.alloc(16 - payload.length % 16, 0)
      payload = Buffer.concat([payload, padPayload]);
    }

    let checksum = 0xbeaf;
    for (let i = 0; i < payload.length; i++) {
      checksum += payload[i];
    }
    checksum = checksum & 0xffff;

    packet[0x34] = checksum & 0xff;
    packet[0x35] = checksum >> 8;

    const cipher = crypto.createCipheriv('aes-128-cbc', this.key, this.iv);
    payload = cipher.update(payload);

    packet = Buffer.concat([packet, payload]);

    checksum = 0xbeaf;
    for (let i = 0; i < packet.length; i++) {
      checksum += packet[i];
    }
    checksum = checksum & 0xffff;
    packet[0x20] = checksum & 0xff;
    packet[0x21] = checksum >> 8;

    if (debug) log(`\x1b[33m[DEBUG]\x1b[0m (${this.mac.toString('hex')}) Sending packet: ${packet.toString('hex')} ix:${ix}`);

    socket.send(packet, 0, packet.length, this.host.port, this.host.address, (err) => {
      if (debug && err) log('\x1b[33m[DEBUG]\x1b[0m send packet error', err);
      callback?.(err, ix);
    })
  }	     

  onPayloadReceivedSync (err, ix, payload) {
    const param = payload[0];
    const { log, debug } = this;

    // if (debug) log(`\x1b[33m[DEBUG]\x1b[0m (${this.mac.toString('hex')}) Payload received: ${payload.toString('hex')} param: ${param}`);

    if (this.actives.has(ix)) {
      const command = this.actives.get(ix);
      this.actives.delete(ix);
      this.emit(command, err, ix, payload);
      return true;
    }
    // if (err) {
    //   return true;
    // } else {
    //   return false;
    // }

    return false;
  }

  // onPayloadReceived (err, payload) {
  //   const param = payload[0];
  //   const { log, debug } = this;

  //   if (debug) log(`\x1b[33m[DEBUG]\x1b[0m (${this.mac.toString('hex')}) Payload received: ${payload.toString('hex')}`);

  //   switch (param) {
  //     case 0x1: { //RM3 Check temperature
  //       const temp = (payload[0x4] * 10 + payload[0x5]) / 10.0;
  //       this.emit('temperature', temp);
  //       break;
  //     }
  //     case 0x4: { //get from check_data
  //       const data = Buffer.alloc(payload.length - 4, 0);
  //       payload.copy(data, 0, 4);
  //       this.emit('rawData', data);
  //     }
  //     case 0x09: { // Check RF Frequency found from RM4 Pro
  //       const data = Buffer.alloc(1, 0);
  //       payload.copy(data, 0, 0x6);
  //       if (data[0] !== 0x1) break;
  //       this.emit('rawRFData', data);
  //       break;
  //     }
  //     case 0xa9:
  //     case 0xb0: 
  //     case 0xb1: 
  //     case 0xb2: { //RF Code returned
  //       this.emit('rawData', payload);
  //       break;
  //     }
  //     case 0xa: { //RM3 Check temperature and humidity
  //       const temp = (payload[0x6] * 100 + payload[0x7]) / 100.0;
  //       const humidity = (payload[0x8] * 100 + payload[0x9]) / 100.0;
  //       this.emit('temperature',temp, humidity);
  //       break;
  //     }
  //     case 0x1a: { //get from check_data
  //       const data = Buffer.alloc(1, 0);
  //       payload.copy(data, 0, 0x4);
  //       if (data[0] !== 0x1) break;
  //       this.emit('rawRFData', data);
  //       break;
  //     }
  //     case 0x1b: { // Check RF Frequency found from RM Pro
  //       const data = Buffer.alloc(1, 0);
  //       payload.copy(data, 0, 0x4);
  //       if (data[0] !== 0x1 && !this.rm4Type) break; //Check if Fequency identified
  //       this.emit('rawRFData2', data); 
  //       break;
  //     }
  //     case 0x26: { //get IR code from check_data
  //       this.emit('rawData', payload);
  //       break;
  //     }
  //     case 0x5e: { //get data from learning
  //       const data = Buffer.alloc(payload.length - 4, 0);
  //       payload.copy(data, 0, 6);
  //       this.emit('rawData', data);
  //       break;
  //     }
  //   }
  // }

  // Externally Accessed Methods

  async sendPacketSync(command, packet, debug = false) {
    const { log } = this;
    const x = new Error('Trace:');
    return await new Promise((resolve, reject) => {
      this.sendPacket(0x6a, packet, debug, async (senderr, ix0) => {
	const commandx = `${command}${ix0}`;
	this.actives.set(ix0, commandx);
	// log(this.actives);
	if (senderr) {
	  return reject(`${senderr}`);	// sendPacket error
	}
	const timeout = setTimeout(() => {
	  this.removeListener(commandx, listener);
	  this.actives.delete(ix0);
	  return reject(`Timed out of 10 second(s) in response to ${command}. source:${ix0}`);
	}, 10*1000);
	const listener = (status, ix, payload) => {
	  clearTimeout(timeout);
	  // if (ix0 !== ix) {
	  //   return reject(`Unexpected command sequence of ${command}. source:${ix0} response:${ix}`);
	  // }
	  if (status) {
	    if (debug) log(`\x1b[33m[DEBUG]\x1b[0m Error response of ${command}. source:${ix0} Device:${this.mac.toString('hex')} listener:${this.emitter.listenerCount(command)}`);
	    resolve(null);
	  } else {
	    if (debug) log(`\x1b[33m[DEBUG]\x1b[0m Succeed response of ${command}. source:${ix0} Device:${this.mac.toString('hex')} listener:${this.emitter.listenerCount(command)}`);
	    resolve(payload);
	  }
	}
	await this.once(commandx, listener);
      });
    }).catch((e) => {
      if (debug) log(`Failed to send/receive packet. ${e} Device:${this.mac.toString('hex')} ${x.stack.substring(7)}`);
    })
  }
  
  async checkData(debug = false) {
    let packet = new Buffer.from([0x04, 0x00, 0x00, 0x00]);
    packet = Buffer.concat([this.request_header, packet]);
    const payload = await this.sendPacketSync('checkData', packet, debug)
    if (payload) {
      const byte0 = 4 + this.request_header.length;
      const data = Buffer.alloc(payload.length - byte0, 0);
      payload.copy(data, 0, byte0);
      this.emit('rawData', data);
      return data;
    }
    return null;
  }

  async sendData (data, debug = false) {
    let packet = new Buffer.from([0x02, 0x00, 0x00, 0x00]);
    let header = Buffer.alloc(this.request_header.length);
    this.request_header.copy(header); 
    if (this.request_header.length) header.writeUint16LE(4 + data.length);
    packet = Buffer.concat([header, packet, data]);
    // this.log(`Device:${this.mac.toString('hex')} ${packet.toString('hex')}`);
    await this.sendPacketSync('sendData', packet, debug)
  }

  async enterLearning(debug = false) {
    let packet = new Buffer.from([0x03, 0x00, 0x00, 0x00]);
    packet = Buffer.concat([this.request_header, packet]);
    await this.sendPacketSync('enterLearning', packet, debug)
  }

  async checkTemperature(debug = false) {
    if (this.request_header.length) {
      let packet = new Buffer.from([0x24, 0x00, 0x00, 0x00]);
      packet = Buffer.concat([this.request_header, packet]);
      const payload = await this.sendPacketSync('checkSensors', packet, debug)
      if (payload) {
        const temp = (payload[0x6] * 10 + payload[0x7]) / 10.0;
        const humidity = (payload[0x8] * 100 + payload[0x9]) / 100.0;
	// this.log(`Device:${this.mac.toString('hex')} ${payload.toString('hex')}, temp:${temp}, humidity:${humidity}`);
        this.emit('temperature',temp, humidity);
	return {
          "temperature": temp,
          "humidity": humidity
	}
      }
      return undefined;
    } else {
      let packet = new Buffer.from([0x1, 0x00, 0x00, 0x00]);
      packet = Buffer.concat([this.request_header, packet]);
      const payload = await this.sendPacketSync('checkTemperature', packet, debug)
      if (payload) {
        const temp = (payload[0x4] * 10 + payload[0x5]) / 10.0;
	// this.log(`Device:${this.mac.toString('hex')} Temperature:${temp}`);
        this.emit('temperature', temp);
	return temp;
      }
      return undefined;
    }
  }
  checkSensors = this.checkTemperature;
  checkHumidity = this.checkTemperature;

  async cancelLearn(debug = false) {
    let packet = new Buffer.from([0x1e, 0x00, 0x00, 0x00]);
    packet = Buffer.concat([this.request_header, packet]);
    await this.sendPacketSync('cancelLearning', packet, debug);
  }
  cancelLearning = this.cancelLearn;
  cancelSweepFrequency = this.cancelLearn;
  
  addRFSupport() {
    this.enterRFSweep = async (debug = false) => {
      let packet = new Buffer.from([0x19, 0x00, 0x00, 0x00]);
      packet = Buffer.concat([this.request_header, packet]);
      await this.sendPacketSync('enterRFSweep', packet, debug);
    }
    this.sweepFrequency = this.enterRFSweep;

    this.checkRFData = async (debug = false) => {
      let packet = new Buffer.from([0x1a, 0x00, 0x00, 0x00]);
      packet = Buffer.concat([this.request_header, packet]);
      const payload = await this.sendPacketSync('checkFrequency', packet, debug);
      if (payload) {
	const byte0 = 4 + this.request_header.length;
	// this.log(`Device:${this.mac.toString('hex')} ${payload.toString('hex')} ${payload.readUint32LE(byte0 + 1)/1000}MHz`);
        const data = Buffer.alloc(5, 0);
        payload.copy(data, 0, byte0);
        if (payload[byte0]) {
	  this.emit('rawRFData', data);
	}
	return {
	  locked: payload[byte0],
	  frequency: payload.readUint32LE(byte0 + 1)/1000
	}
      }
      return null;
    }
    this.checkFrequency = this.checkRFData;

    this.checkRFData2 = async (frequency, debug = false) => {
      let packet = new Buffer.from([0x1b, 0x00, 0x00, 0x00]);
      let header = Buffer.alloc(this.request_header.length);
      this.request_header.copy(header); 
      // packet = Buffer.concat([this.request_header, packet]);
      if (frequency) {
	const data = Buffer.alloc(4, 0);
	data.writeUint32LE(Math.round(frequency * 1000));
	packet = Buffer.concat([packet, data]);
	if (this.request_header.length) header.writeUint16LE(8);
      }
      packet = Buffer.concat([header, packet]);
      const payload = await this.sendPacketSync('checkRFData', packet, debug);
      if (payload) {
	const byte0 = 4 + this.request_header.length;
	// this.log(`Device:${this.mac.toString('hex')} ${payload.toString('hex')}`);
        const data = Buffer.alloc(1, 0);
        payload.copy(data, 0, byte0);
        this.emit('rawRFData2', data);
      }
    }
    this.findRFPacket = this.checkRFData2;
  }
}

module.exports = Broadlink;
