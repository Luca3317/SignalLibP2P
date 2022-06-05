package signallibp2p

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/Luca3317/libsignalcopy/keys/identity"
	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/state/record"
	"github.com/Luca3317/libsignalcopy/util/keyhelper"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

type signalSession struct {
	initiator bool

	sessionBuilder session.Builder
	sessionCipher  *session.Cipher

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

	// These might belong in transport; Irrelevant for testing
	prekeyStore       InMemoryPreKey
	identityStore     InMemoryIdentityKey
	signedprekeyStore InMemorySignedPreKey
	sessionStore      InMemorySession
	registrationID    uint32
}

/* 	Creates a new secure Signal Session
TODO: Possibly hardcode listener values (currently read from drive)
*/
func newSignalSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*signalSession, error) {

	// TODO: FINISH INITIALIZING S (SIGNALSESSION)
	s := &signalSession{
		initiator: initiator,

		prekeyStore:       *NewInMemoryPreKey(),
		signedprekeyStore: *NewInMemorySignedPreKey(),
		sessionStore:      *NewInMemorySession(serialize.NewJSONSerializer()),
		registrationID:    keyhelper.GenerateRegistrationID(),

		localID:  tpt.localID,
		localKey: tpt.privateKey,
		remoteID: remote,

		insecureConn:   insecure,
		insecureReader: bufio.NewReader(insecure),
	}

	var (
		localRegID uint32
		identity   *identity.KeyPair
		prekey     *record.PreKey
		sigPreKey  *record.SignedPreKey
	)

	// If dialer, generate new values; otherwise use stored
	if initiator {
		var err error
		identity, err = keyhelper.GenerateIdentityKeyPair()
		if err != nil {
			logger.Debug("\nFailed to generate IdentityKeypair\n")
			return nil, err
		}

		prekeys, err := keyhelper.GeneratePreKeys(0, 1, serialize.NewJSONSerializer().PreKeyRecord)
		if err != nil {
			logger.Debug("\nFailed to generate Prekey\n")
			return nil, err
		}
		prekey = prekeys[0]

		sigPreKey, err = keyhelper.GenerateSignedPreKey(identity, 0, serialize.NewJSONSerializer().SignedPreKeyRecord)
		if err != nil {
			logger.Debug("\nFailed to generate SignedPrekey\n")
			return nil, err
		}

		localRegID = keyhelper.GenerateRegistrationID()

	} else {
		retr, err := retrievable.ReadBundle()
		if err != nil {
			logger.Debug("\nFailed to ReadBundle\n")
			return nil, err
		}
		identity = &retr.IdentityKeyPair
		prekey = &retr.PreKey
		sigPreKey = &retr.SignedPreKey
		localRegID = retr.Ids.RegID
	}

	s.identityStore = *NewInMemoryIdentityKey(identity, localRegID)
	s.prekeyStore.StorePreKey(prekey.ID().Value, prekey)
	s.signedprekeyStore.StoreSignedPreKey(sigPreKey.ID(), sigPreKey)

	// the go-routine we create to run the handshake will
	// write the result of the handshake to the respCh.
	respCh := make(chan error, 1)
	go func() {
		respCh <- s.handshake(ctx)
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
