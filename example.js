import net from 'net';
import { contentId, Handshake, Header, Message, Peers } from './proto.js';

// some known peers
const knownPeers = [
	{ host: '52.51.9.86', port: 6868 },
	{ host: '5.75.231.53', port: 6868 },
	{ host: '168.119.155.201', port: 6868 },
];

// try to connect to random known peer
const random = Math.floor(Math.random() * knownPeers.length);
const peer = knownPeers[random];
const client = net.createConnection(peer);

client.on('ready', () => {
	console.log('ready');
	// say hello
	const handshake = new Handshake();
	client.write(handshake.toBuffer());

	// ask for known peers
	const getPeersMessage = new Message({ contentId: contentId.getPeers });
	client.write(getPeersMessage.toBuffer());
});

client.once('data', data => {
	console.log(data);
	console.log(Handshake.fromBuffer(data))

	let buffer = Buffer.from([]);
	let targetLength = 0;

	client.on('data', data => {
		if (buffer.length === 0) targetLength = data.readUInt32BE() + 4
		buffer = Buffer.concat([buffer, data])
		if (buffer.length < targetLength) return
		// try to unmarshal message
		const targetBuffer = buffer.subarray(0, targetLength)
		buffer = buffer.subarray(targetLength)
		if (buffer.length >= 4) targetLength = buffer.readInt32BE() + 4
		const message = Message.fromBuffer(targetBuffer)
		console.log(message);
		switch (message.header.contentId) {
			// node asks for known peers
			case contentId.getPeers:
				// just reply with empty peers
				const peers = new Message({
					contentId: contentId.peers,
					payload: new Peers(),
				});
				client.write(peers.toBuffer());
				break;
		}
	});
});

client.on('error', error => {
	console.log(`Error: ${error}`)
});

client.on('timeout', () => {
	client.destroy('timeout');
})

client.on('close', () => {
	console.log('closed');
});