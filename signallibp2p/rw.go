package signallibp2p

import (
	"github.com/Luca3317/libsignalcopy/logger"
)

const MaxPlaintextLength = 32768
const LengthPrefixLength = 2
const MaxTransportMsgLength = 0xffff

func (s *signalSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	logger.Debug("reading... ")
	_, err := s.insecureConn.Read(buf)
	if err != nil {
		logger.Debug("FAILED TO READ")
	} else {
		logger.Debug("Success; read ", buf, " (", string(buf), ")")
	}

	dec, err := s.decrypt(buf)
	if err != nil {
		return len(buf), err
	}

	copy(buf, dec)

	return len(buf), nil
}

func (s *signalSession) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	total := len(data)
	enc, err := s.encrypt(data)
	if err != nil {
		return 0, err
	}

	logger.Debug("writing ", enc, " (", string(enc), ") ...")
	_, err = s.insecureConn.Write(enc)
	if err != nil {
		logger.Debug("FAILED TO WRITE")
		return total, err
	} else {
		logger.Debug("Success;")
	}

	return total, nil
}

// writeMsgInsecure writes to the insecureConn conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *signalSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
