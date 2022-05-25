package signallibp2p

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
)

func (s *signalSession) Handshake(ctx context.Context) (err error) {
	_, err = retrievable.CreateBundleRaw()
	if err != nil {
		log.Fatal("failed to create bundle")
	}
	ret, err := retrievable.ReadBundle()
	if err != nil {
		log.Fatal("failed to create bundle")
	}

	builder := session.NewBuilder(
		NewInMemorySession(serialize.NewJSONSerializer()),
		NewInMemoryPreKey(), NewInMemorySignedPreKey(),
		NewInMemoryIdentityKey(&ret.IdentityKeyPair, ret.Ids.RegID),
		protocol.NewSignalAddress("kaka "+strconv.Itoa(int(ret.Ids.RegID)), ret.Ids.DevID),
		serialize.NewJSONSerializer(),
	)

	bundle := prekey.NewBundle(
		ret.Ids.RegID, ret.Ids.DevID,
		ret.PreKey.ID(), ret.SignedPreKey.ID(),
		ret.PreKey.KeyPair().PublicKey(), ret.SignedPreKey.KeyPair().PublicKey(),
		ret.SignedPreKey.Signature(), ret.IdentityKeyPair.PublicKey(),
	)

	err = builder.ProcessBundle(bundle)
	if err != nil {
		log.Fatal("failll")
	}
	fmt.Printf("Ayooo")

	return errors.New("not implemetned")
}
