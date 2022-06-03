package signallibp2p

import (
	"context"
	"strings"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	pool "github.com/libp2p/go-buffer-pool"
)

const buffersize = 10000

func (s *signalSession) Handshake(ctx context.Context) (err error) {

	logger.Debug("\n\nHandshake enter data:\ninitiator: ", s.initiator, "\nLocalAddr: ", s.insecureConn.LocalAddr().String(), "\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(), "\nNetworkName: ", s.insecureConn.LocalAddr().Network(), "\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), "\n\n\n")

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
		plaintext := []byte("This is my initial handshake message!!! AINT THAT CRAZY WTF")
		message, err := s.sessionCipher.Encrypt(plaintext)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt data with new cipher\n", err, "\n")
			return err
		}

		// Step 4: Send first Message
		logger.Debug("\nHandshake-Dialer\nI will need ", len(message.Serialize()), " bytes in buffer \n")
		logger.Debug("\nHandshake-Dialer\nStep 4: Sending first Message\n")
		i, err := s.writeMsgInsecure(message.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")

		// Step 5: Receive first response
		logger.Debug("\nHandshake-Dialer\nStep 5: Receive first response\n")
		hbuf := pool.Get(buffersize)
		defer pool.Put(hbuf)

		_, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to read message!\n", err, "\n")
			return err
		}

		responseMessage, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed make signal message from bytes!\n", err, "\n")
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(responseMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to decrypt message!\n", err, "\n")
			return err
		}

		logger.Debug("\nHandshake-Dialer\nReturning; Decrypted: ", deResponse, "\n guess im done? \n")

	} else {

		// Step 0: Preparations (including ReadBundle and session.NewBuilder)
		logger.Debug("\nHandshake-Listener\nStep 0: Preparations (incl. Readbundle and session.newbuilder)\n")
		remoteAddr := protocol.NewSignalAddress("dialer", 2)

		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: Receive first message
		hbuf := pool.Get(buffersize)
		defer pool.Put(hbuf)

		_, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nReceived msg!;\n", hbuf, "\n")
		logger.Debug("\nFirst nil at: ", strings.IndexByte(string(hbuf), 0), "\n")
		logger.Debug("\nCut version:: ", hbuf[:strings.IndexByte(string(hbuf), 0)], "\n")

		receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().PreKeySignalMessage, serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to make prekeymessage from byteys!\n", err, "\n")
			return err
		}

		unsignedPreKeyID, err := s.sessionBuilder.Process(receivedMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to process receivedmessage!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nHeres the retrieved prekey id: ", unsignedPreKeyID, "; dunoo what do with this lol!\n")

		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		msg, err := s.sessionCipher.Decrypt(receivedMessage.WhisperMessage())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to decrypt prekeysignal!\n", err, "\n")
			return err
		}

		logger.Debug("\nHandshake-Listener\nDecryption result: ", msg, "\n")

		plainTextResponse := []byte("jahi!")
		response, err := s.sessionCipher.Encrypt(plainTextResponse)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to decrypt response!\n", err, "\n")
			return err
		}

		logger.Debug("\nHandshake-Listener\nStep x: Sending first response\n")
		_, err = s.writeMsgInsecure(response.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to write response!\n", err, "\n")
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
