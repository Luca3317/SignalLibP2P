package signallibp2p

import (
	"github.com/Luca3317/libsignalcopy/logger"
)

const MaxPlaintextLength = 4096
const LengthPrefixLength = 2
const MaxTransportMsgLength = 100000

// TODO: consider long messages
// encrypt
// etc
func (s *signalSession) Read(buf []byte) (int, error) {
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
func (s *signalSession) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	i, err := s.insecureConn.Write(data)
	if err != nil {
		logger.Debug("\n\nFAILED TO WRITE IN WRITE\n\n")
	}

	return i, err
}

// writeMsgInsecure writes to the insecureConn conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *signalSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
