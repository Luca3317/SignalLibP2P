package signallibp2p

import (
	"encoding/binary"
	"io"

	"github.com/Luca3317/libsignalcopy/logger"
	pool "github.com/libp2p/go-buffer-pool"
	"golang.org/x/crypto/poly1305"
)

const MaxPlaintextLength = 32768
const LengthPrefixLength = 2
const MaxTransportMsgLength = 0xffff

// Read reads from the secure connection, returning plaintext data in `buf`.
//
// Honours io.Reader in terms of behaviour.
func (s *signalSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	// 1. If we have queued received bytes:
	//   1a. If len(buf) < len(queued), saturate buf, update seek pointer, return.
	//   1b. If len(buf) >= len(queued), copy remaining to buf, release queued buffer back into pool, return.
	//
	// 2. Else, read the next message off the wire; next_len is length prefix.
	//   2a. If len(buf) >= next_len, copy the message to input buffer (zero-alloc path), and return.
	//   2b. If len(buf) >= (next_len - length of Authentication Tag), get buffer from pool, read encrypted message into it.
	//       decrypt message directly into the input buffer and return the buffer obtained from the pool.
	//   2c. If len(buf) < next_len, obtain buffer from pool, copy entire message into it, saturate buf, update seek pointer.
	if s.qbuf != nil {
		// we have queued bytes; copy as much as we can.
		copied := copy(buf, s.qbuf[s.qseek:])
		s.qseek += copied
		if s.qseek == len(s.qbuf) {
			// queued buffer is now empty, reset and release.
			pool.Put(s.qbuf)
			s.qseek, s.qbuf = 0, nil
		}
		return copied, nil
	}

	// length of the next encrypted message.
	nextMsgLen, err := s.readNextInsecureMsgLen()
	if err != nil {
		return 0, err
	}
	logger.Debug("Read; next msg will be ", nextMsgLen)

	// If the buffer is atleast as big as the encrypted message size,
	// we can read AND decrypt in place.
	if len(buf) >= nextMsgLen {
		logger.Debug("buffer was big enough")
		if err := s.readNextMsgInsecure(buf[:nextMsgLen]); err != nil {
			return 0, err
		}
		logger.Debug("read ", buf[:nextMsgLen])

		dbuf, err := s.decrypt(buf[:nextMsgLen])
		if err != nil {
			return 0, err
		}
		logger.Debug("decrypted ", dbuf)

		return len(dbuf), nil
	}
	logger.Debug("buffer was NOT big enough")

	// otherwise, we get a buffer from the pool so we can read the message into it
	// and then decrypt in place, since we're retaining the buffer (or a view thereof).
	cbuf := pool.Get(nextMsgLen)
	if err := s.readNextMsgInsecure(cbuf); err != nil {
		return 0, err
	}
	logger.Debug("read ", cbuf)

	if s.qbuf, err = s.decrypt(cbuf); err != nil {
		return 0, err
	}
	logger.Debug("decrypted ", s.qbuf)

	// copy as many bytes as we can; update seek pointer.
	s.qseek = copy(buf, s.qbuf)

	return s.qseek, nil
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

	// TODO replace case 1, check how big metadata is for ciphertext compared to plaintext
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

		b, err := s.encrypt(data[written:end])
		if err != nil {
			return 0, err
		}

		logger.Debug("\nI was gonna write ", string(data), " -> ", b)
		var prefixbuf [2]byte
		var sief []byte
		copy(sief, append(prefixbuf[:], b...))
		logger.Debug("\nI would now write ", sief)
		binary.BigEndian.PutUint16(sief, uint16(len(sief)-LengthPrefixLength))
		logger.Debug("\nI will now write ", sief)

		_, err = s.writeMsgInsecure(sief)
		if err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// readNextInsecureMsgLen reads the length of the next message on the insecureConn channel.
func (s *signalSession) readNextInsecureMsgLen() (int, error) {
	_, err := io.ReadFull(s.insecureReader, s.rlen[:])
	if err != nil {
		return 0, err
	}

	return int(binary.BigEndian.Uint16(s.rlen[:])), err
}

func (s *signalSession) readNextMsgInsecure(buf []byte) error {
	_, err := io.ReadFull(s.insecureReader, buf)
	return err
}

/* func (s *signalSession) Read(buf []byte) (int, error) {
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
} */

// writeMsgInsecure writes to the insecureConn conn.
// data will be prefixed with its length in bytes, written as a 16-bit uint in network order.
func (s *signalSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
