package signallibp2p

import (
	"errors"

	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
)

func (s *signalSession) encrypt(plaintext []byte) ([]byte, error) {
	if s.sessionCipher == nil {
		return nil, errors.New("Cannot encrypt; handshake incomplete")
	}

	cipher, err := s.sessionCipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	logger.Debug("encrypted a message :", string(plaintext), " -> ", string(cipher.Serialize()))

	return cipher.Serialize(), nil
}

func (s *signalSession) decrypt(ciphertext []byte) ([]byte, error) {
	if s.sessionCipher == nil {
		return nil, errors.New("Cannot decrypt; handshake incomplete")
	}

	msg, err := protocol.NewSignalMessageFromBytes(ciphertext, serialize.NewJSONSerializer().SignalMessage)
	if err != nil {
		return nil, err
	}

	plain, err := s.sessionCipher.Decrypt(msg)
	if err != nil {
		return nil, err
	}

	logger.Debug("decrypted a message :", string(ciphertext), " -> ", string(plain))

	return plain, nil
}
