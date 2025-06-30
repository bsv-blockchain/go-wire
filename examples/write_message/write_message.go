package main

import (
	"bufio"
	"github.com/bsv-blockchain/go-wire"
	"os"
)

func main() {
	// Use the most recent protocol version supported by the package and the
	// main bitcoin network.
	pVer := wire.ProtocolVersion
	bsvNet := wire.MainNet

	// User a writer to stdout for example usage
	conn := bufio.NewWriterSize(os.Stdout, 1024)

	// Create a new getaddr bitcoin message.
	msg := wire.NewMsgGetAddr()

	// Writes a bitcoin message msg to conn using the protocol version
	// pver, and the bitcoin network bsvnet.  The return is a possible
	// error.
	err := wire.WriteMessage(conn, msg, pVer, bsvNet)
	if err != nil {
		panic(err)
	}
}
