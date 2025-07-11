// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

const localhostAddr = "127.0.0.1"

// TestAddr tests the MsgAddr API.
func TestAddr(t *testing.T) {
	pver := ProtocolVersion

	// Ensure the command is expected value.
	wantCmd := "addr"
	msg := NewMsgAddr()

	assertCommand(t, msg, wantCmd)

	// Ensure max payload is expected value for a latest protocol version.
	// Num addresses (varInt) + max allowed addresses.
	wantPayload := uint64(30009)
	assertMaxPayload(t, msg, pver, wantPayload)

	// Ensure NetAddresses are added properly.
	tcpAddr := &net.TCPAddr{IP: net.ParseIP(localhostAddr), Port: 8333}
	na := NewNetAddress(tcpAddr, SFNodeNetwork)
	err := msg.AddAddress(na)
	if err != nil {
		t.Errorf("AddAddress: %v", err)
	}

	if msg.AddrList[0] != na {
		t.Errorf("AddAddress: wrong address added - got %v, want %v",
			spew.Sprint(msg.AddrList[0]), spew.Sprint(na))
	}

	// Ensure the address list is cleared properly.
	msg.ClearAddresses()

	if len(msg.AddrList) != 0 {
		t.Errorf("ClearAddresses: address list is not empty - "+
			"got %v [%v], want %v", len(msg.AddrList),
			spew.Sprint(msg.AddrList[0]), 0)
	}

	// Ensure adding more than the max allowed addresses per message returns
	// error.
	for i := 0; i < MaxAddrPerMsg+1; i++ {
		err = msg.AddAddress(na)
	}

	if err == nil {
		t.Errorf("AddAddress: expected error on too many addresses " +
			"not received")
	}

	err = msg.AddAddresses(na)
	if err == nil {
		t.Errorf("AddAddresses: expected error on too many addresses " +
			"not received")
	}

	// Ensure max payload is expected value for protocol versions before
	// timestamp was added to NetAddress.
	// Num addresses (varInt) + max allowed addresses.
	pver = NetAddressTimeVersion - 1
	wantPayload = uint64(26009)
	assertMaxPayload(t, msg, pver, wantPayload)

	// Ensure max payload is expected value for protocol versions before
	// multiple addresses were allowed.
	// Num addresses (varInt) + a single net addresses.
	pver = MultipleAddressVersion - 1
	wantPayload = uint64(35)
	assertMaxPayload(t, msg, pver, wantPayload)
}

// TestAddrWire tests the MsgAddr wire encode and decode for various numbers
// of addresses and protocol versions.
func TestAddrWire(t *testing.T) {
	// A couple of NetAddresses to use for testing.
	na := &NetAddress{
		Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Services:  SFNodeNetwork,
		IP:        net.ParseIP(localhostAddr),
		Port:      8333,
	}
	na2 := &NetAddress{
		Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Services:  SFNodeNetwork,
		IP:        net.ParseIP("192.168.0.1"),
		Port:      8334,
	}

	// Empty address message.
	noAddr := NewMsgAddr()
	noAddrEncoded := []byte{
		0x00, // Varint for number of addresses
	}

	// Address message with multiple addresses.
	multiAddr := NewMsgAddr()
	_ = multiAddr.AddAddresses(na, na2)
	multiAddrEncoded := []byte{
		0x02,                   // Varint for number of addresses
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SFNodeNetwork
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SFNodeNetwork
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x00, 0x01, // IP 192.168.0.1
		0x20, 0x8e, // Port 8334 in big-endian

	}

	tests := []struct {
		in   *MsgAddr        // Message to encode
		out  *MsgAddr        // Expected decoded message
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version with no addresses.
		{
			noAddr,
			noAddr,
			noAddrEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Latest protocol version with multiple addresses.
		{
			multiAddr,
			multiAddr,
			multiAddrEncoded,
			ProtocolVersion,
			BaseEncoding,
		},

		// Protocol version MultipleAddressVersion-1 with no addresses.
		{
			noAddr,
			noAddr,
			noAddrEncoded,
			MultipleAddressVersion - 1,
			BaseEncoding,
		},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BsvEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BsvEncode #%d error %v", i, err)
			continue
		}

		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BsvEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		var msg MsgAddr

		rbuf := bytes.NewReader(test.buf)
		err = msg.Bsvdecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("Bsvdecode #%d error %v", i, err)
			continue
		}

		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("Bsvdecode #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestAddrWireErrors performs negative tests against wire encode and decode
// of MsgAddr to confirm error paths work correctly.
func TestAddrWireErrors(t *testing.T) {
	pver := ProtocolVersion
	pverMA := MultipleAddressVersion
	wireErr := &MessageError{}

	// A couple of NetAddresses to use for testing.
	na := &NetAddress{
		Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Services:  SFNodeNetwork,
		IP:        net.ParseIP(localhostAddr),
		Port:      8333,
	}
	na2 := &NetAddress{
		Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Services:  SFNodeNetwork,
		IP:        net.ParseIP("192.168.0.1"),
		Port:      8334,
	}

	// Address message with multiple addresses.
	baseAddr := NewMsgAddr()
	_ = baseAddr.AddAddresses(na, na2)
	baseAddrEncoded := []byte{
		0x02,                   // Varint for number of addresses
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SFNodeNetwork
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
		0x29, 0xab, 0x5f, 0x49, // Timestamp
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SFNodeNetwork
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x00, 0x01, // IP 192.168.0.1
		0x20, 0x8e, // Port 8334 in big-endian

	}

	// Message that forces an error by having more than the max allowed
	// addresses.
	maxAddr := NewMsgAddr()
	for i := 0; i < MaxAddrPerMsg; i++ {
		_ = maxAddr.AddAddress(na)
	}

	maxAddr.AddrList = append(maxAddr.AddrList, na)
	maxAddrEncoded := []byte{
		0xfd, 0x03, 0xe9, // Varint for number of addresses (1001)
	}

	tests := []struct {
		in       *MsgAddr        // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force error in addresses count
		{baseAddr, baseAddrEncoded, pver, BaseEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in an address list.
		{baseAddr, baseAddrEncoded, pver, BaseEncoding, 1, io.ErrShortWrite, io.EOF},
		// Force error with greater than max inventory vectors.
		{maxAddr, maxAddrEncoded, pver, BaseEncoding, 3, wireErr, wireErr},
		// Force error with greater than max inventory vectors for
		// protocol versions before multiple addresses were allowed.
		{maxAddr, maxAddrEncoded, pverMA - 1, BaseEncoding, 3, wireErr, wireErr},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := test.in.BsvEncode(w, test.pver, test.enc)

		if reflect.TypeOf(err) != reflect.TypeOf(test.writeErr) {
			t.Errorf("BsvEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		var msgError *MessageError
		if !errors.As(err, &msgError) {
			if !errors.Is(err, test.writeErr) {
				t.Errorf("BsvEncode #%d wrong error got: %v, "+
					"want: %v", i, err, test.writeErr)
				continue
			}
		}

		// Decode from wire format.
		var msg MsgAddr

		r := newFixedReader(test.max, test.buf)
		err = msg.Bsvdecode(r, test.pver, test.enc)

		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("Bsvdecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		// For errors which are not of type MessageError, check them for
		// equality.
		if !errors.As(err, &msgError) {
			if !errors.Is(err, test.readErr) {
				t.Errorf("Bsvdecode #%d wrong error got: %v, "+
					"want: %v", i, err, test.readErr)
				continue
			}
		}
	}
}
