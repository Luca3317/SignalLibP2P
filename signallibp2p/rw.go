package signallibp2p

import (
	"strings"

	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
)

const MaxPlaintextLength = 4096
const LengthPrefixLength = 2
const MaxTransportMsgLength = 100000

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

	logger.Debug("test: prolly wont work (prolly shouldnt either\n")
	logger.Debug("encrypting ", string(data))
	msg, err := s.sessionCipher.Encrypt(data)
	if err != nil {
		logger.Debug("failed to encrypt ???")
		return i, err
	}
	logger.Debug("Result: ", msg.Serialize())
	newmsg, err := protocol.NewSignalMessageFromBytes(msg.Serialize(), serialize.NewJSONSerializer().SignalMessage)
	if err != nil {
		logger.Debug("failed to make sig message ???")
		return i, err
	}
	sief, err := s.sessionCipher.Decrypt(newmsg)
	if err != nil {
		logger.Debug("failed to decrypt ???")
		return i, err
	}

	logger.Debug("Original: ", string(data), "\nNew: ", string(sief))

	return i, err
}

// TODO: consider long messages
// encrypt
// etc
func (s *signalSession) Reads(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	logger.Debug("Reading...")
	i, err := s.insecureConn.Read(buf)
	if err != nil {
		logger.Debug("Reading FAIL\n")
		logger.Debug(err)
		return i, err
	} else {
		logger.Debug("Reading SUCC\n")
		logger.Debug("Read: ", buf)
	}

	logger.Debug("Making message from ", buf[:strings.IndexByte(string(buf), 0)], "...")
	msg, err := protocol.NewSignalMessageFromBytes(buf, serialize.NewJSONSerializer().SignalMessage)
	if err != nil {
		logger.Debug("Making msg FAIL\n")
		logger.Debug(err)
		return i, err
	} else {
		logger.Debug("Making msg SUCC\n")
	}

	logger.Debug("Decrypting ", msg, "...")
	dec, err := s.sessionCipher.Decrypt(msg)
	if err != nil {
		logger.Debug("Decrypting FAIL\n")
		logger.Debug(err)
		return i, err
	} else {
		logger.Debug("Decrypting UCC\n")
	}

	logger.Debug("Read Result\n", string(dec), "\n", dec)
	return len(dec), nil
}

// TODO: consider long messages
// encrypt
// etc
func (s *signalSession) Writes(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	total := len(data)

	logger.Debug("Encrypting ", string(data), "...")
	msg, err := s.sessionCipher.Encrypt(data)
	if err != nil {
		logger.Debug("Encrypt FAIL\n")
		logger.Debug(err)
		return 0, err
	} else {
		logger.Debug("Encrypt SUCC\n")
	}

	logger.Debug("Writing ", msg.Serialize(), "...")
	_, err = s.insecureConn.Write(msg.Serialize())
	if err != nil {
		logger.Debug("Write FAIL\n")
		logger.Debug(err)
		return total, err
	} else {
		logger.Debug("Write SUCC\n")
	}

	return total, nil
}

// writeMsgInsecure writes to the insecureConn conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *signalSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
