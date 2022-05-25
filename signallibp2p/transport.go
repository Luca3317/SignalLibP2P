package signallibp2p

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/sec"
)

const ID = "/signal"

type Transport struct {
	localID    peer.ID
	privateKey crypto.PrivKey
}

func New(privkey crypto.PrivKey) (*Transport, error) {
	localID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	return &Transport{
		localID:    localID,
		privateKey: privkey,
	}, nil
}

// SecureInbound runs the Noise handshake as the responder.
// If p is empty, connections from any peer are accepted.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSignalSession(t, ctx, insecure, p, false)
}

// SecureOutbound runs the Noise handshake as the initiator.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSignalSession(t, ctx, insecure, p, true)
}
