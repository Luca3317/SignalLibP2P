package signallibp2p

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	pool "github.com/libp2p/go-buffer-pool"
)

func (s *signalSession) Handshake(ctx context.Context) (err error) {

	logger.Info("\nUSING UPDATED\n")

	if s.initiator {

		// Step 0 (TODO: Remove): Generate necessary data
		_, err = retrievable.CreateBundleRaw()
		if err != nil {
			log.Fatal("failed to create bundle")
		}

		// Step 1: Create PreKey Bundle (as well as session builder)
		ret, err := retrievable.ReadBundle()
		if err != nil {
			log.Fatal("failed to create bundle")
		}

		bundle := prekey.NewBundle(
			ret.Ids.RegID, ret.Ids.DevID,
			ret.PreKey.ID(), ret.SignedPreKey.ID(),
			ret.PreKey.KeyPair().PublicKey(), ret.SignedPreKey.KeyPair().PublicKey(),
			ret.SignedPreKey.Signature(), ret.IdentityKeyPair.PublicKey(),
		)

		// TODO: is this the right way to create addresses?
		remoteAddress := protocol.NewSignalAddress("kaka "+strconv.Itoa(int(ret.Ids.RegID)), ret.Ids.DevID)
		builder := session.NewBuilder(
			NewInMemorySession(serialize.NewJSONSerializer()),
			NewInMemoryPreKey(), NewInMemorySignedPreKey(),
			NewInMemoryIdentityKey(&ret.IdentityKeyPair, ret.Ids.RegID),
			remoteAddress,
			serialize.NewJSONSerializer(),
		)

		// Step 2: Process retrieved PreKey Bundle to establish session
		err = builder.ProcessBundle(bundle)
		if err != nil {
			log.Fatal("\nFailed to process bundle!\n", err)
		}
		fmt.Printf("\nSuccessfully processed bundle")

		// Step 3: Create a Session Cipher to encrypt Messages
		// TODO: maybe store the sessioncipher (also maybe builder etc) in signalsession
		// TODO: maybe use own encrypt function here already
		plaintextMessage := []byte("Hello!")
		logger.Info("Plaintext message: ", string(plaintextMessage))
		sessionCipher := session.NewCipher(builder, remoteAddress)
		message, err := sessionCipher.Encrypt(plaintextMessage)
		if err != nil {
			log.Fatal("\nFailed to encrypt message:\n", err)
		}

		logger.Info("\nEncrypted message:\n", message)
		i, err := s.writeMsgInsecure(message.Serialize())
		if err != nil {
			log.Fatal("\nFailed to write message:\n", err)
		}

		logger.Info("\n\nSO FAR SO GOOD; wrote ", i, "bytes\n\n")

	} else {

		// Receiver session creation
		mlen, err := s.readNextInsecureMsgLen()
		if err != nil {
			log.Fatal("\nFailed to read message len:\n", err)
		}

		hbuf := pool.Get(mlen)
		defer pool.Put(hbuf)

		logger.Info("\n\nSO FAR SO GOOD, mlen: ", mlen, "\n\n")

		err = s.readNextMsgInsecure(hbuf)
		if err != nil {
			log.Fatal("\nFailed to read message:\n", err)
		}

		_, err = protocol.NewPreKeySignalMessageFromBytes(
			hbuf, serialize.NewJSONSerializer().PreKeySignalMessage,
			serialize.NewJSONSerializer().SignalMessage,
		)
		if err != nil {
			log.Fatal("\nFailed to make prekeysignalmessage from bytes:\n", err)
		}

		logger.Info("\n\nSO FAR SO GOOD 2\n\n")

	}

	return nil
}
