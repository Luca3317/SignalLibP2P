package signallibp2p

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/state/record"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

type signalSession struct {
	initiator bool

	localID   peer.ID
	remoteID  peer.ID
	localKey  crypto.PrivKey
	remoteKey crypto.PubKey

	readLock  sync.Mutex
	writeLock sync.Mutex

	insecureConn net.Conn
	// insecureReader *bufio.Reader idk if needed
}

func newSignalSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, initiator bool) (*signalSession, error) {

	ss := &signalSession{
		insecureConn: insecure,
		initiator:    initiator,
		localID:      tpt.localID,
		localKey:     tpt.privateKey,
		remoteID:     remote,
	}

	if initiator {
		retrievedRaw := retrievable.ReadBundleRaw()

		myprekey, err := record.NewPreKeyFromBytes(retrievedRaw.PreKey, serialize.NewJSONSerializer().PreKeyRecord)
		if err != nil {
			return nil, err
		}

		sigprekey, err := record.NewSignedPreKeyFromBytes(retrievedRaw.SignedPreKey, serialize.NewJSONSerializer().SignedPreKeyRecord)
		if err != nil {
			return nil, err
		}

		pubraw, privraw := retrievable.ReadIDKeyPairRaw()
		pub, err := crypto.UnmarshalPublicKey(pubraw)
		if err != nil {
			return nil, err
		}
		priv, err := crypto.UnmarshalPrivateKey(privraw)
		if err != nil {
			return nil, err
		}

		retrieved := &retrievable.Retrievable{
			Ids:                 retrievedRaw.Ids,
			IdentityKeyPairPub:  pub,
			IdentityKeyPairPriv: priv,
			PreKey:              *myprekey,
			SignedPreKey:        *sigprekey,
		}

		Handshake(tpt, retrieved)
	}

	//	Handshake()

	return ss, errors.New("not implemented!")
}

// secure session type methods
func (s *signalSession) LocalAddr() net.Addr {
	return s.insecureConn.LocalAddr()
}

func (s *signalSession) LocalPeer() peer.ID {
	return s.localID
}

func (s *signalSession) Close() error {
	return s.insecureConn.Close()
}

func (s *signalSession) LocalPrivateKey() crypto.PrivKey {
	return s.localKey
}

func (s *signalSession) Read(buf []byte) (int, error) {
	return 0, errors.New("not implemented!")
}

func (s *signalSession) Write(data []byte) (int, error) {
	return 0, errors.New("not implemented!")
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
