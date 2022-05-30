package signallibp2p

import (
	"context"
	"log"
	"runtime/debug"
	"strconv"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	pool "github.com/libp2p/go-buffer-pool"
)

func (s *signalSession) Handshake(ctx context.Context) error {

	logger.Debug(debug.Stack())

	serializer := serialize.NewJSONSerializer()

	// If youre the dialer
	if s.initiator {

		logger.Debug("\nStarting Handshake-Dialer\nwith partner ", s.remoteID, "\n")

		// Step -1: Reconstruct listener's public Key (remove? ideally replace with network version)
		// TODO: implement

		// Step 0: Preparations (including ReadBundle)
		logger.Debug("\nHandshake-Dialer\nReading Bundle\n")

		retrieved, err := retrievable.ReadBundle()
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to ReadBundle!\n")
			return err
		}

		// TODO: is this the right way to create addresses?
		remoteAddress := protocol.NewSignalAddress("kaka "+strconv.Itoa(int(retrieved.Ids.RegID)), retrieved.Ids.DevID)
		builder := session.NewBuilder(
			NewInMemorySession(serialize.NewJSONSerializer()),
			NewInMemoryPreKey(), NewInMemorySignedPreKey(),
			NewInMemoryIdentityKey(&retrieved.IdentityKeyPair, retrieved.Ids.RegID),
			remoteAddress,
			serialize.NewJSONSerializer(),
		)

		// Step 1: Create PreKey Bundle (and process it)
		logger.Debug("\nHandshake-Dialer\nCreated address ", remoteAddress.String(), " for listener (correct?)\n")

		retrievedPreKeyBundle := prekey.NewBundle(
			retrieved.Ids.RegID, retrieved.Ids.DevID,
			retrieved.PreKey.ID(), retrieved.SignedPreKey.ID(),
			retrieved.PreKey.KeyPair().PublicKey(),
			retrieved.SignedPreKey.KeyPair().PublicKey(),
			retrieved.SignedPreKey.Signature(),
			retrieved.IdentityKeyPair.PublicKey(),
		)

		logger.Debug("\nHandshake-Dialer\nBuilding Dialers session using ProcessBundle\n")
		err = builder.ProcessBundle(retrievedPreKeyBundle)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to ProcessBundle!\n")
			return err
		}

		// Step 2: Create SessionCipher
		logger.Debug("\nHandshake-Dialer\nCreating SessionCipher")
		s.sessionCipher = session.NewCipher(builder, remoteAddress)

		logger.Debug("\nHandshake-Dialer\nTesting SessionCipher")
		plainText := []byte("TestMessage")
		cipherText, err := s.sessionCipher.Encrypt(plainText)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; SessionCipher Test failed!\n")
			return err
		} else {
			logger.Debug("\nHandshake-Dialer\nPlainText: ", plainText, "; CipherText: ", cipherText, "\n")
		}

		// Step 3: Send Message
		// TODO: probably need to create a different kind of message? this just says "hello"?
		logger.Debug("\nHandshake-Dialer\nSending first message\n")

		i, err := s.writeMsgInsecure(cipherText.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write message!\n")
			return err
		}

		logger.Debug("\nHandshake-Dialer\nI wrote ", i, "bytes (possibly; idk what that value means)\n")

	} else {

		logger.Debug("\nStarting Handshake-Listener\nwith partner ", s.remoteID, "\n")
		mlen, err := s.readNextInsecureMsgLen()
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to readNextInsecureMsgLen!\n")
			return err
		}

		hbuf := pool.Get(mlen)
		defer pool.Put(hbuf)

		logger.Debug("\nHandshake-Listener\nReading first message\n")
		err = s.readNextMsgInsecure(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read first message\n")
			return err
		}

		logger.Debug("\nHandshake-Dialer\nMaking PreKeyMessage from read bytes\n")
		_, err = protocol.NewPreKeySignalMessageFromBytes(
			hbuf, serialize.NewJSONSerializer().PreKeySignalMessage,
			serialize.NewJSONSerializer().SignalMessage,
		)
		if err != nil {
			log.Fatal("nHandshake-Dialer\nReturning; Failed to make PreKeyMessage from bytes\n")
		}
	}

	logger.Debug("\n\nFinished handshake without raising errors!\n\n")
	return nil
}

/* func (s *signalSession) Handshake(ctx context.Context) (err error) {

	logger.Info("\nUSING UPDATED\nHeres the stack")
	debug.PrintStack()

	logger.Debug("\nrestoring key\n")
	keybytes, err := retrievable.ReadLibP2PKeys()
	if err != nil {
		log.Fatal("failed to read libp2p key\n", err)
	}
	key, err := crypto.UnmarshalPublicKey(keybytes)
	if err != nil {
		log.Fatal("failed to unmarshal libp2p key\n", err)
	}
	s.remoteKey = key

	retrievable.SaveLibP2PKey(s.LocalPublicKey())

	if s.initiator {

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
		s.sessionCipher = session.NewCipher(builder, remoteAddress)
		message, err := s.sessionCipher.Encrypt(plaintextMessage)
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

		pubkeybytes, err := retrievable.ReadLibP2PKeys()
		if err != nil {
			log.Fatal("failed to read libp2p keys\n", err)
		}

		pubkey, err := crypto.UnmarshalPublicKey(pubkeybytes)
		if err != nil {
			log.Fatal("failed to unmarshal key\n", err)
		}

		s.remoteKey = pubkey

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
} */
