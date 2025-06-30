package main

import (
	"bytes"
	"log"
	"net"
	"time"

	"github.com/bsv-blockchain/go-wire"
)

func main() {
	// Use the most recent protocol version supported by the package and the
	// main bitcoin network.
	pVer := wire.ProtocolVersion
	bsvNet := wire.MainNet
	var buf bytes.Buffer

	// Construct proper version message
	addrYou := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}
	you := wire.NewNetAddress(addrYou, wire.SFNodeNetwork)
	you.Timestamp = time.Time{} // Version message has zero value timestamp.
	addrMe := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	me := wire.NewNetAddress(addrMe, wire.SFNodeNetwork)
	me.Timestamp = time.Time{} // Version message has zero value timestamp.
	msgVersion := wire.NewMsgVersion(me, you, 123123, 0)

	// Write a message to buffer
	_, err := wire.WriteMessageN(&buf, msgVersion, pVer, bsvNet)
	if err != nil {
		panic(err)
	}

	// construct read buffer from bytes
	readBuf := bytes.NewReader(buf.Bytes())

	// Reads and validates the next bitcoin message from conn using the
	// protocol version pver and the bitcoin network bsvnet.  The returns
	// are a wire.Message, a []byte which contains the unmarshalled
	// raw payload, and a possible error.
	var msg wire.Message
	msg, _, err = wire.ReadMessage(readBuf, pVer, bsvNet)
	if err != nil {
		panic(err)
	}

	log.Println(msg)
}
