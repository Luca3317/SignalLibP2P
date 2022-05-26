package signallibp2p

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

type signalSession struct {
	initiator bool

	sessionCipher *session.Cipher

	localID   peer.ID
	localKey  crypto.PrivKey
	remoteID  peer.ID
	remoteKey crypto.PubKey

	readLock  sync.Mutex
	writeLock sync.Mutex

	insecureConn   net.Conn
	insecureReader *bufio.Reader // to cushion io read syscalls
	// we don't buffer writes to avoid introducing latency; optimisation possible. // TODO revisit

	// TODO: these are for the insecure rw fucntions
	// which might be wrong for signal
	qseek int     // queued bytes seek value.
	qbuf  []byte  // queued bytes buffer.
	rlen  [2]byte // work buffer to read in the incoming message length.
}

// TODO
// copy goroutine from nosie
func newSignalSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*signalSession, error) {

	s := &signalSession{
		insecureConn:   insecure,
		insecureReader: bufio.NewReader(insecure),
		initiator:      initiator,
		localID:        tpt.localID,
		localKey:       tpt.privateKey,
		remoteID:       remote,
	}

	err := s.Handshake(ctx)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *signalSession) LocalAddr() net.Addr {
	return s.insecureConn.LocalAddr()
}

func (s *signalSession) LocalPeer() peer.ID {
	return s.localID
}

func (s *signalSession) LocalPrivateKey() crypto.PrivKey {
	return s.localKey
}

func (s *signalSession) LocalPublicKey() crypto.PubKey {
	return s.localKey.GetPublic()
}

func (s *signalSession) RemoteAddr() net.Addr {
	return s.insecureConn.RemoteAddr()
}

func (s *signalSession) RemotePeer() peer.ID {
	return s.remoteID
}

func (s *signalSession) RemotePublicKey() crypto.PubKey {
	return s.remoteKey
}

func (s *signalSession) SetDeadline(t time.Time) error {
	return s.insecureConn.SetDeadline(t)
}

func (s *signalSession) SetReadDeadline(t time.Time) error {
	return s.insecureConn.SetReadDeadline(t)
}

func (s *signalSession) SetWriteDeadline(t time.Time) error {
	return s.insecureConn.SetWriteDeadline(t)
}

func (s *signalSession) Close() error {
	return s.insecureConn.Close()
}

func (s *signalSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	err := s.readNextMsgInsecure(buf)
	if err != nil {
		logger.Debug("\nfailed to read safely\n")
		return 0, err
	}

	message, err := protocol.NewSignalMessageFromBytes(buf, serialize.NewJSONSerializer().SignalMessage)
	if err != nil {
		logger.Debug("\nfailed to make message\n")
		return 0, err
	}

	plaintext, err := s.sessionCipher.Decrypt(message)
	if err != nil {
		logger.Debug("\nfailed to decrypt message\n")
		return 0, err
	}

	copy(buf, plaintext)
	return 0, nil
}

func (s *signalSession) Write(buf []byte) (int, error) {
	return s.writeMsgInsecure(buf)
}

/*
// Copied straight from noise
// Read reads from the secure connection, returning plaintext data in `buf`.
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

	// If the buffer is atleast as big as the encrypted message size,
	// we can read AND decrypt in place.
	if len(buf) >= nextMsgLen {
		if err := s.readNextMsgInsecure(buf[:nextMsgLen]); err != nil {
			return 0, err
		}

		dbuf, err := s.decrypt(buf[:0], buf[:nextMsgLen])
		if err != nil {
			return 0, err
		}

		return len(dbuf), nil
	}

	// otherwise, we get a buffer from the pool so we can read the message into it
	// and then decrypt in place, since we're retaining the buffer (or a view thereof).
	cbuf := pool.Get(nextMsgLen)
	if err := s.readNextMsgInsecure(cbuf); err != nil {
		return 0, err
	}

	if s.qbuf, err = s.decrypt(cbuf[:0], cbuf); err != nil {
		return 0, err
	}

	// copy as many bytes as we can; update seek pointer.
	s.qseek = copy(buf, s.qbuf)

	return s.qseek, nil
}

// these values probably make no sense; from noise
const MaxTransportMsgLength = 0xffff
const MaxPlaintextLength = MaxTransportMsgLength - poly1305.TagSize
const LengthPrefixLength = 2

// Copied stragith from noise
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
}*/
