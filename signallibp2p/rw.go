package signallibp2p

import (
	"encoding/binary"
	"io"
)

// TODO: Insecure functions copied from noise; might be wrong for signal
// readNextInsecureMsgLen reads the length of the next message on the insecureConn channel.
func (s *signalSession) readNextInsecureMsgLen() (int, error) {
	_, err := io.ReadFull(s.insecureReader, s.rlen[:])
	if err != nil {
		return 0, err
	}

	return int(binary.BigEndian.Uint16(s.rlen[:])), err
}

// readNextMsgInsecure tries to read exactly len(buf) bytes into buf from
// the insecureConn channel and returns the error, if any.
// Ideally, for reading a message, you'd first want to call `readNextInsecureMsgLen`
// to determine the size of the next message to be read from the insecureConn channel and then call
// this function with a buffer of exactly that size.
func (s *signalSession) readNextMsgInsecure(buf []byte) error {
	_, err := io.ReadFull(s.insecureReader, buf)
	return err
}

// writeMsgInsecure writes to the insecureConn conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *signalSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
