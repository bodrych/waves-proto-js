const net = require('net');
const _ = require('lodash');
const blake2 = require('blake2');
const SmartBuffer = require('smart-buffer').SmartBuffer;

const maxHeaderLength = 17;
const headerMagic = Buffer.from('12345678', 'hex');

const headerSizeWithPayload = 17;
const headerSizeWithoutPayload = 13;

const contentId = {
	getPeers: 0x1,
	peers: 0x2,
	signatures: 0x15,
	getBlock: 0x16,
	block: 0x17,
	score: 0x18,
	transaction: 0x19,
	invMicroblock: 0x1A,
	checkpoint: 0x64,
	microblockRequest: 27,
	microblock: 28,
};

const headerContentIdPosition = 8;

class Handshake {
	constructor({
		appName = 'wavesW',
		nodeName = 'observer',
		version = [1, 1, 6],
		nonce = 0n,
		declAddress = null,
		timestamp = BigInt((new Date()).getTime()),
	} = {}) {
		this.appName = appName;
		this.nodeName = nodeName;
		this.version = version;
		this.nonce = nonce;
		this.declAddress = declAddress;
		this.timestamp = timestamp;
	}

	static fromBuffer(data) {
		const buf = SmartBuffer.fromBuffer(data);
		const appName = buf.readString(buf.readUInt8());
		const version = _.times(3, () => buf.readUInt32BE());
		const nodeName = buf.readString(buf.readUInt8());
		const nonce = buf.readBigUInt64BE();
		const declAddrSize = buf.readUInt32BE();
		let declAddress;
		// 0 for no declared address, 8 for ipv4 address + port, 20 for ipv6 address + port
		if (declAddrSize === 0) {
			declAddress = null;
		} else if (declAddrSize !== 0 && declAddrSize !== 8 && declAddrSize !== 20) {
			throw new Error(`An invalid declared address length: ${declAddrSize}`);
		} else {
			const ip = _.times(declAddrSize, () => buf.readUInt8());
			const port = buf.readUInt32BE();
			if (net.isIP(ip.join('.')) === 0) {
				throw new Error('Invalid address');
			}
			if (port > 2 ** 16 - 1 || port < 0) {
				throw new Error('Invalid port');
			}
			declAddress = { ip, port };
		}
		const timestamp = buf.readBigUInt64BE();
		return new this({
			appName,
			nodeName,
			version,
			nonce,
			declAddress,
			timestamp,
		});
	}

	toBuffer() {
		const buf = new SmartBuffer();
		buf.writeUInt8(Buffer.from(this.appName).length);
		buf.writeString(this.appName);
		_.each(this.version, value => buf.writeUInt32BE(value))
		buf.writeUInt8(Buffer.from(this.nodeName).length);
		buf.writeString(this.nodeName);
		buf.writeBigUInt64BE(this.nonce);
		if (this.declAddress === null) {
			buf.writeUInt32BE(0);
		} else {
			buf.writeUInt32BE(8);
			_.each(this.declAddress.ip, value => buf.writeUInt8(value));
			buf.writeUInt32BE(this.declAddress.port);
		}
		buf.writeBigUInt64BE(this.timestamp);
		return buf.toBuffer();
	}
}

class Message {
	constructor({
		contentId,
		header,
		payload = null,
	} = {}) {
		this.payload = payload;
		if (!contentId) {
			this.header = header;
		} else {
			this.header = new Header({
				contentId,
				packetLength: payload ? headerSizeWithPayload + payload.toBuffer().length - 4 : headerSizeWithoutPayload - 4,
				payloadLength: payload ? payload.toBuffer().length : 0,
			});
			if (payload) {
				const h = blake2.createHash('blake2b');
				h.update(this.payload.toBuffer());
				this.header.payloadChecksum = h.digest().slice(0, 4);
			}
		}
	}

	static fromBuffer(data) {
		if (data.length < headerSizeWithoutPayload) {
			throw new Error('Message is too short');
		} else if (data.length < headerSizeWithPayload) {
			const header = Header.fromBuffer(data);
			return new this({
				header,
				payload: null,
			});
		} else {
			const header = Header.fromBuffer(data.slice(0, headerSizeWithPayload));
			let payload = null;
			switch (header.contentId) {
				case contentId.peers:
					payload = Peers.fromBuffer(data.slice(headerSizeWithPayload, data.length));
					break;
			}
			return new this({
				header,
				payload,
			});
		}
	}

	toBuffer() {
		const buf = new SmartBuffer();
		buf.writeBuffer(this.header.toBuffer());
		if (this.payload) buf.writeBuffer(this.payload.toBuffer());
		return buf.toBuffer();
	}

	setChecksum() {
		if (payload) {
			const h = blake2.createHash('blake2b');
			h.update(this.payload.toBuffer());
			this.header.payloadChecksum = h.digest();
		}
	}
}

class Header {
	constructor({
		contentId,
		packetLength,
		payloadLength,
		payloadChecksum,
		magicBytes = headerMagic,
	} = {}) {
		this.packetLength = packetLength;
		this.magicBytes = magicBytes;
		this.contentId = contentId;
		this.payloadLength = payloadLength;
		this.payloadChecksum = payloadChecksum;
	}

	static fromBuffer(data) {
		const buf = SmartBuffer.fromBuffer(data);
		const packetLength = buf.readUInt32BE();
		const magicBytes = buf.readBuffer(4);
		const contentId = buf.readUInt8();
		const payloadLength = buf.readUInt32BE();
		let payloadChecksum = null;
		if (payloadLength > 0) {
			payloadChecksum = buf.readBuffer(4);
		}
		return new this({
			contentId,
			packetLength,
			payloadLength,
			payloadChecksum,
			magicBytes,
		});
	}

	toBuffer() {
		const buf = new SmartBuffer();
		buf.writeUInt32BE(this.packetLength);
		buf.writeBuffer(this.magicBytes);
		buf.writeUInt8(this.contentId);
		buf.writeUInt32BE(this.payloadLength);
		if (this.payloadChecksum) {
			buf.writeBuffer(this.payloadChecksum);
		}
		return buf.toBuffer();
	}
}


class Peers {
	constructor({ peers = [] } = {}) {
		this.peers = peers;
	}

	static fromBuffer(data) {
		const buf = SmartBuffer.fromBuffer(data);
		const peersCount = buf.readUInt32BE();
		const peers = _.times(peersCount, value => {
			const ip = _.times(4, value => buf.readUInt8());
			const port = buf.readUInt32BE();
			return { ip, port };
		});
		return new this({ peers });
	}

	toBuffer() {
		const buf = new SmartBuffer();
		buf.writeUInt32BE(this.peers.length);
		_.each(this.peers, value => {
			buf.writeBuffer(Buffer.from(value.ip));
			buf.writeUInt32BE(value.port);
		});
		return buf.toBuffer();
	}
}

module.exports = exports = {
	contentId,
	Handshake,
	Header,
	Message,
	Peers,
}