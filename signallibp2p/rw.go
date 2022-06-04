package signallibp2p

import (
	"github.com/Luca3317/libsignalcopy/logger"
)

const MaxPlaintextLength = 32768
const LengthPrefixLength = 2
const MaxTransportMsgLength = 0xffff

func (s *signalSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	s.writeLock.Lock()
	defer s.readLock.Unlock()
	defer s.writeLock.Unlock()

	logger.Debug("reading... ")
	i, err := s.insecureConn.Read(buf)
	if err != nil {
		logger.Debug("FAILED TO READ")
	} else {
		logger.Debug("Success; read ", buf, " (", string(buf), ")")
	}

	//total := len(buf)

	return i, err
}

func (s *signalSession) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	s.readLock.Lock()
	defer s.writeLock.Unlock()
	defer s.readLock.Unlock()

	//	total := len(data)

	logger.Debug("writing ", data, " (", string(data), ") ...")
	i, err := s.insecureConn.Write(data)
	if err != nil {
		logger.Debug("FAILED TO WRITE")
	} else {
		logger.Debug("Success;")
	}

	return i, err
}

// writeMsgInsecure writes to the insecureConn conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *signalSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
