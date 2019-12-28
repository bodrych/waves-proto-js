const net = require('net');
const _ = require('lodash');
const { contentId, Handshake, Header, Message, Peers } = require('waves-proto-js');

// some known peers
const knownPeers = [
	{ host: '13.228.86.201', port: 6868 },
	{ host: '13.229.0.149', port: 6868 },
	{ host: '18.195.170.147', port: 6868 },
	{ host: '34.253.153.4', port: 6868 },
	{ host: '35.156.19.4', port: 6868 },
	{ host: '52.50.69.247', port: 6868 },
	{ host: '52.52.46.76', port: 6868 },
	{ host: '52.57.147.71', port: 6868 },
	{ host: '52.214.55.18', port: 6868 },
	{ host: '54.176.190.226', port: 6868 },
	{ host: '45.77.139.254', port: 6868 },
];

// try to connect to random known peer
const client = net.createConnection(_.sample(knownPeers));

client.on('ready', () => {
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

	client.on('data', data => {
		console.log(data);
		// try to unmarshal message
		const message = Message.fromBuffer(data);
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
			// node sends known peers
			case contentId.peers:
				console.log(message);
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