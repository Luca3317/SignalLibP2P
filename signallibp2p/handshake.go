package signallibp2p

import (
	"context"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	pool "github.com/libp2p/go-buffer-pool"
)

func (s *signalSession) Handshake(ctx context.Context) (err error) {

	// If this is the dialer
	if s.initiator {

		// Step 0: Preparations (including ReadBundle and session.NewBuilder)
		logger.Debug("\nHandshake-Dialer\nStep 0: Preparations (incl. Readbundle and session.newbuilder)\n")
		retr, err := retrievable.ReadBundle()
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; failed to readbundle\n", err, "\n")
			return err
		}

		remoteAddr := protocol.NewSignalAddress("listener", 1)
		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: "Retrieve Bundle from server"
		logger.Debug("\nHandshake-Dialer\nRetrieve Bundle from Server (read from HDD)\n")
		retrievedBundle := prekey.NewBundle(
			retr.Ids.RegID, retr.Ids.DevID,
			retr.PreKey.ID(), retr.SignedPreKey.ID(),
			retr.PreKey.KeyPair().PublicKey(), retr.SignedPreKey.KeyPair().PublicKey(),
			retr.SignedPreKey.Signature(),
			retr.IdentityKeyPair.PublicKey(),
		)

		// Step 2: Process retrieved Bundle
		logger.Debug("\nHandshake-Dialer\nStep 2: Process retrieved Bundle\n")
		err = s.sessionBuilder.ProcessBundle(retrievedBundle)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to process bundle\n", err, "\n")
			return err
		}

		// Step 3: Create SessionCipher
		logger.Debug("\nHandshake-Dialer\nCreating SessionCipher\n")
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		plaintext := []byte("Hello")
		message, err := s.sessionCipher.Encrypt(plaintext)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt data with new cipher\n", err, "\n")
			return err
		}

		// Step 4: Send first Message
		logger.Debug("\nHandshake-Dialer\nStep 4: Sending first Message\n")
		i, err := s.writeMsgInsecure(message.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write message!\n", err, "\n")
			return err
		}

		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")

		// TODO FINISH

	} else {

		// Step 0: Preparations (including ReadBundle and session.NewBuilder)
		logger.Debug("\nHandshake-Listener\nStep 0: Preparations (incl. Readbundle and session.newbuilder)\n")
		remoteAddr := protocol.NewSignalAddress("dialer", 2)

		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: Receive first message
		mlen, err := s.readNextInsecureMsgLen()
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read messageLength!\n", err, "\n")
			return err
		}

		hbuf := pool.Get(mlen + 1000)
		defer pool.Put(hbuf)

		err = s.readNextMsgInsecure(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read message!\n", err, "\n")
			return err
		}

	}

	if s.initiator {
		logger.Debug("\nHandshake-Dialer\nFinished Handshake without errors!\n")
	} else {
		logger.Debug("\nHandshake-Listener\nFinished Handshake without errors!\n")
	}

	return nil
}
