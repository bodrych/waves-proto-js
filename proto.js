import net from 'net';
import blake2 from 'blake2';
import { SmartBuffer } from 'smart-buffer';

const maxHeaderLength = 17;
const headerMagic = Buffer.from('12345678', 'hex');

const headerSizeWithPayload = 17;
const headerSizeWithoutPayload = 13;

export const contentId = {
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

export class Handshake {
	constructor({
		appName = 'wavesW',
		nodeName = 'observer',
		version = [1, 4, 0],
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
		const version = Array.from({ length: 3 }, () => buf.readUInt32BE());
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
			const ip = Array.from({ length: declAddrSize - 4 }, () => buf.readUInt8());
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
		for (const value of this.version) {
			buf.writeUInt32BE(value);
		}
		buf.writeUInt8(Buffer.from(this.nodeName).length);
		buf.writeString(this.nodeName);
		buf.writeBigUInt64BE(this.nonce);
		if (this.declAddress === null) {
			buf.writeUInt32BE(0);
		} else {
			buf.writeUInt32BE(8);
			for (const value of this.declAddress.ip) {
				buf.writeUInt8(value);
			}
			buf.writeUInt32BE(this.declAddress.port);
		}
		buf.writeBigUInt64BE(this.timestamp);
		return buf.toBuffer();
	}
}

export class Message {
	constructor({
		contentId,
		header,
		payload = null,
	} = {}) {
		this.payload = payload;
		if (!contentId) {
			this.header = header;
		} else {
			const payloadLength = payload ? payload.toBuffer().length : 0
			this.header = new Header({
				contentId,
				packetLength: payload ? headerSizeWithPayload + payload.toBuffer().length - 4 : headerSizeWithoutPayload - 4,
				payloadLength,
			});
			if (payload && payloadLength > 0) {
				const h = blake2.createHash('blake2b', { digestLength: 32 });
				h.update(this.payload.toBuffer());
				this.header.payloadChecksum = h.digest().subarray(0, 4);
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
}

export class Header {
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


export class Peers {
	constructor({ peers = [] } = {}) {
		this.peers = peers;
	}

	static fromBuffer(data) {
		const buf = SmartBuffer.fromBuffer(data);
		const peersCount = buf.readUInt32BE();
		const peers = Array.from({ length: peersCount }, () => {
			const ip = Array.from({ length: 4 }, () => buf.readUInt8());
			const port = buf.readUInt32BE();
			return { ip, port };
		});
		return new this({ peers });
	}

	toBuffer() {
		const buf = new SmartBuffer();
		buf.writeUInt32BE(this.peers.length);
		for (const { ip, port } of this.peers) {
			buf.writeBuffer(Buffer.from(ip));
			buf.writeUInt32BE(port);
		}
		return buf.toBuffer();
	}
}
