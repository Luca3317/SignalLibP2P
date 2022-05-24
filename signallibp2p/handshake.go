package signallibp2p

import (
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/util/keyhelper"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
)

func Handshake(tpt *Transport, retrieved *retrievable.Retrievable) error {

	fmt.Printf("\n\ntesting processbundle\n\n")

	prekeys, _ := keyhelper.GeneratePreKeys(0, 10, serialize.NewJSONSerializer().PreKeyRecord)
	idkeypair, _ := keyhelper.GenerateIdentityKeyPair()
	sigprekey, _ := keyhelper.GenerateSignedPreKey(idkeypair, 0, serialize.NewJSONSerializer().SignedPreKeyRecord)

	retrievedBundle := prekey.NewBundle(
		keyhelper.GenerateRegistrationID(),
		12,
		prekeys[0].ID(),
		sigprekey.ID(),
		prekeys[0].KeyPair().PublicKey(),
		sigprekey.KeyPair().PublicKey(),
		sigprekey.Signature(),
		idkeypair.PublicKey(),
	)

	tpt.buildSession(protocol.NewSignalAddress("name "+strconv.Itoa((int)(retrievedBundle.RegistrationID())), retrievedBundle.DeviceID()), serialize.NewJSONSerializer())
	err := tpt.sessionBuilder.ProcessBundle(retrievedBundle)
	if err != nil {
		log.Fatal("this part failed", err)
	} else {
		log.Fatal("it worked huh so far so ogofdodoadfnasd")
	}
	/*
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
		} */

	return errors.New("not implemented!")
}
