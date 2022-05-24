package signallibp2p

import (
	"context"
	"fmt"
	"net"

	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

// ID is the protocol ID for noise
const ID = "/signal"

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureConn
type Transport struct {
	localID    peer.ID
	privateKey crypto.PrivKey

	// Stores
	sessionStore      *InMemorySession
	preKeyStore       *InMemoryPreKey
	signedPreKeyStore *InMemorySignedPreKey
	identityStore     *InMemoryIdentityKey

	sessionBuilder session.Builder

	serializer serialize.Serializer
}

// probably very unfinished, depends on struct
func New(privKey crypto.PrivKey) (*Transport, error) {
	fmt.Printf("OK\n\n BIN HIER!!!!!!!!!!!!!!!!!!! \n}\n")
	localID, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	// TODO
	// prior, generate localregisrtation id and use as input for identitykeystore
	serializer := serialize.NewJSONSerializer()
	return &Transport{
		localID:           localID,
		privateKey:        privKey,
		sessionStore:      NewInMemorySession(serializer),
		preKeyStore:       NewInMemoryPreKey(),
		signedPreKeyStore: NewInMemorySignedPreKey(),
		identityStore:     NewInMemoryIdentityKey(retrievable.ConvertIDKeysLibp2pToSig(privKey.GetPublic(), privKey), 0),
		serializer:        *serializer,
	}, nil
}

func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSignalSession(t, ctx, insecure, p, false)
}

func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSignalSession(t, ctx, insecure, p, true)
}

// buildSession will build a session with the given address
func (t *Transport) buildSession(address *protocol.SignalAddress, serializer *serialize.Serializer) {
	t.sessionBuilder = *session.NewBuilder(
		t.sessionStore,
		t.preKeyStore,
		t.signedPreKeyStore,
		t.identityStore,
		address,
		serializer,
	)
}
