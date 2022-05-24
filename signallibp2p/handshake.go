package signallibp2p

import (
	"errors"
	"log"
	"strconv"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
)

func Handshake(tpt *Transport, retrieved *retrievable.Retrievable) error {

	retrievedBundle := prekey.NewBundle(
		retrieved.Ids.RegID,
		retrieved.Ids.DevID,
		retrieved.PreKey.ID(),
		retrieved.SignedPreKey.ID(),
		retrieved.PreKey.KeyPair().PublicKey(),
		retrieved.SignedPreKey.KeyPair().PublicKey(),
		retrieved.SignedPreKey.Signature(),
		retrievable.ConvertIDKeysLibp2pToSig(retrieved.IdentityKeyPairPub, retrieved.IdentityKeyPairPriv).PublicKey(),
	)

	tpt.buildSession(protocol.NewSignalAddress("name "+strconv.Itoa((int)(retrievedBundle.RegistrationID())), retrievedBundle.DeviceID()), serialize.NewJSONSerializer())
	err := tpt.sessionBuilder.ProcessBundle(retrievedBundle)
	if err != nil {
		log.Fatal("this part failed", err)
	} else {
		log.Fatal("it worked huh so far so ogofdodoadfnasd")
	}

	return errors.New("not implemented!")
}
