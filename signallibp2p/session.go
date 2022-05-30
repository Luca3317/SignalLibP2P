package signallibp2p

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

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

	// the go-routine we create to run the handshake will
	// write the result of the handshake to the respCh.
	respCh := make(chan error, 1)
	go func() {
		respCh <- s.Handshake(ctx)
	}()

	select {
	case err := <-respCh:
		if err != nil {
			_ = s.insecureConn.Close()
		}
		return s, err

	case <-ctx.Done():
		// If the context has been cancelled, we close the underlying connection.
		// We then wait for the handshake to return because of the first error it encounters
		// so we don't return without cleaning up the go-routine.
		_ = s.insecureConn.Close()
		<-respCh
		return nil, ctx.Err()
	}
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
