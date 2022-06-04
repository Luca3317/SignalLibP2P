package signallibp2p

import (
	"encoding/binary"
	"io"

	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	pool "github.com/libp2p/go-buffer-pool"
	"golang.org/x/crypto/poly1305"
)

// Read reads from the secure connection, returning plaintext data in `buf`.
//
// Honours io.Reader in terms of behaviour.
func (s *signalSession) Read(buf []byte) (int, error) {

	return s.qseek, nil
}

// readNextInsecureMsgLen reads the length of the next message on the insecureConn channel.
func (s *signalSession) readNextInsecureMsgLen() (int, error) {
	_, err := io.ReadFull(s.insecureReader, s.rlen[:])
	if err != nil {
		return 0, err
	}

	return int(binary.BigEndian.Uint16(s.rlen[:])), err
}

// Write encrypts the plaintext `in` data and sends it on the
// secure connection.
func (s *signalSession) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	var (
		written int
		cbuf    []byte
		total   = len(data)
	)

	if total < MaxPlaintextLength {
		cbuf = pool.Get(total + poly1305.TagSize + LengthPrefixLength)
	} else {
		cbuf = pool.Get(MaxTransportMsgLength + LengthPrefixLength)
	}

	defer pool.Put(cbuf)

	for written < total {
		end := written + MaxPlaintextLength
		if end > total {
			end = total
		}

		b, err := s.encrypt(cbuf[:LengthPrefixLength], data[written:end])
		if err != nil {
			return 0, err
		}

		binary.BigEndian.PutUint16(b, uint16(len(b)-LengthPrefixLength))

		_, err = s.writeMsgInsecure(b)
		if err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// TODO: consider long messages
// encrypt
// etc
func (s *signalSession) ReadOld(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	i, err := s.insecureConn.Read(buf)
	if err != nil {
		logger.Debug("\n\n\nFAILED TO READ IN READ\n\n\n")
	}

	return i, err
}

// TODO: consider long messages
// encrypt
// etc
func (s *signalSession) WriteOld(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	i, err := s.insecureConn.Write(data)
	if err != nil {
		logger.Debug("\n\nFAILED TO WRITE IN WRITE\n\n")
	}

	return i, err
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

func (s *signalSession) sdRead(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	i, err := s.insecureConn.Read(buf)
	if err != nil {
		logger.Debug("\n\n\nFAILED TO READ IN READ\n\n\n")
	}

	return i, err
}

func (s *signalSession) decrypt(out, ciphertext []byte) ([]byte, error) {
	signalmessage, err := protocol.NewSignalMessageFromBytes(ciphertext, serialize.NewJSONSerializer().SignalMessage)
	if err != nil {
		logger.Debug("\n\nCANNOT ; FAILED TO CREAT SIGNALMESSAGE\n", err, "\n\n")
		return nil, err
	}

	ed, err := s.sessionCipher.Decrypt(signalmessage)
	if err != nil {
		logger.Debug("\n\nCANNOT ; FAILED TO DECRPYT\n", err, "\n\n")
		return nil, err
	}

	return ed, nil
}

func (s *signalSession) encrypt(out, plaintext []byte) ([]byte, error) {
	ciphermessage, err := s.sessionCipher.Encrypt(plaintext)
	if err != nil {
		logger.Debug("\n\nCANNOT ENCRYPT; FAILED TO ENCRYPT\n", err, "\n\n")
		return nil, err
	}

	out = ciphermessage.Serialize()
	return ciphermessage.Serialize(), err
}

const MaxPlaintextLength = 4096
const LengthPrefixLength = 0
const MaxTransportMsgLength = 100000
