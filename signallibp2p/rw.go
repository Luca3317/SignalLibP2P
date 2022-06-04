package signallibp2p

import (
	"github.com/Luca3317/libsignalcopy/logger"
)

const MaxPlaintextLength = 16384
const LengthPrefixLength = 2
const MaxTransportMsgLength = 0xffff

func (s *signalSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	logger.Debug("reading... \n")
	i, err := s.insecureConn.Read(buf)
	if err != nil {
		logger.Debug("FAILED TO READ\n")
	} else {
		logger.Debug("Success; read ", buf, " (", string(buf), ")")
	}

	//total := len(buf)

	return i, err
}

func (s *signalSession) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	//	total := len(data)

	logger.Debug("writing ", data, " (", string(data), ") ...")
	i, err := s.insecureConn.Write(data)
	if err != nil {
		logger.Debug("FAILED TO Write\n")
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
