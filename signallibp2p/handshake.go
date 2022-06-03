package signallibp2p

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Luca3317/libsignalcopy/keys/prekey"
	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/session"
	"github.com/Luca3317/libsignalcopy/util/retrievable"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

const buffersize = 10000

func (s *signalSession) oldithinkHandshake(ctx context.Context) (err error) {

	logger.Debug("\n\nHandshake enter data:\ninitiator: ", s.initiator,
		"\nLocalAddr: ", s.insecureConn.LocalAddr().String(),
		"\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(),
		"\nNetworkName: ", s.insecureConn.LocalAddr().Network(),
		"\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), ")",
		"\nLocalPeer: ", s.LocalPeer(),
		"\nRemotePeer: ", s.RemotePeer(),
		"\nLocalPrivKey: ", s.LocalPrivateKey(),
		"\nRemotePubKey: ", s.RemotePublicKey(), "\n\n\n")

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

		// Step 5: Receive and decrypt response; Use payload as key
		logger.Debug("\nHandshake-Dialer\nStep 5: Receive response\n")
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

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to create remote public key from received payload!\n", err, "\n")
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to create remoteID from publickey!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id

		// Step 6: Send acknowledgement with local Key as payload
		logger.Debug("\nHandshake-Dialer\nStep 6: Send acknowledgement with local Key as payload\n")

		localKeyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to marshal local key!\n", err, "\n")
			return err
		}

		ack, err := s.sessionCipher.Encrypt(localKeyM)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt marshalled local key!\n", err, "\n")
			return err
		}

		i, err = s.writeMsgInsecure(ack.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write marshalled local key!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")

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

		_, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read acknowledgement!\n", err, "\n")
			return err
		}

		ackMessage, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to make signal message from ack bytes!\n", err, "\n")
			return err
		}

		deAck, err := s.sessionCipher.Decrypt(ackMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to decrypt ack!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deAck)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to create remote public key from received payload!\n", err, "\n")
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to create remoteID from publickey!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id
	}

	if s.initiator {
		logger.Debug("\nHandshake-Dialer\nFinished Handshake without errors!\n")
	} else {
		logger.Debug("\nHandshake-Listener\nFinished Handshake without errors!\n")
	}

	logger.Debug("\n\nHandshake exit data:\ninitiator: ", s.initiator,
		"\nLocalAddr: ", s.insecureConn.LocalAddr().String(),
		"\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(),
		"\nNetworkName: ", s.insecureConn.LocalAddr().Network(),
		"\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), ")",
		"\nLocalPeer: ", s.LocalPeer(),
		"\nRemotePeer: ", s.RemotePeer(),
		"\nLocalPrivKey: ", s.LocalPrivateKey(),
		"\nRemotePubKey: ", s.RemotePublicKey(), "\n\n\n")

	return nil
}

func (s *signalSession) Handshake(ctx context.Context) (err error) {

	logger.Debug("\n\nHandshake enter data:\ninitiator: ", s.initiator,
		"\nLocalAddr: ", s.insecureConn.LocalAddr().String(),
		"\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(),
		"\nNetworkName: ", s.insecureConn.LocalAddr().Network(),
		"\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), ")",
		"\nLocalPeer: ", s.LocalPeer(),
		"\nRemotePeer: ", s.RemotePeer(),
		"\nLocalPrivKey: ", s.LocalPrivateKey(),
		"\nRemotePubKey: ", s.RemotePublicKey(), "\n\n\n")

	defer func() {
		if rerr := recover(); rerr != nil {
			fmt.Fprintf(os.Stderr, "caught panic: %s\n%s\n", rerr, debug.Stack())
			err = fmt.Errorf("panic in Signal handshake: %s", rerr)
		}
	}()

	// set a deadline to complete the handshake, if one has been supplied.
	// clear it after we're done.
	if deadline, ok := ctx.Deadline(); ok {
		if err := s.SetDeadline(deadline); err == nil {
			// schedule the deadline removal once we're done handshaking.
			defer s.SetDeadline(time.Time{})
		}
	}

	hbuf := pool.Get(buffersize)
	defer pool.Put(hbuf)

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

		// Step 3: Create SessionCipher and encrypt init. message
		logger.Debug("\nHandshake-Dialer\nCreate SessionCipher and encrypt initial message\n")
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		plaintext := []byte("Hallo!")
		message, err := s.sessionCipher.Encrypt(plaintext)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt data with new cipher\n", err, "\n")
			return err
		}

		// Step 4: Send init. message
		logger.Debug("\nHandshake-Dialer\nStep 4: Sending initial Message\n")
		i, err := s.writeMsgInsecure(message.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")

		// Step 5: Read Response Message and use payload as remote key
		logger.Debug("\nHandshake-Dialer\nStep 5: Receive Response Message and use payload as remote key\n")
		i, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nRead ", i, " bytes\n")

		receivedResponse, err := protocol.NewSignalMessageFromBytes(hbuf, serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make message from bytes!\n", err, "\n")
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(receivedResponse)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to decrypt message!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make pubkey!\n", err, "\n")
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make id from Key!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id

		// Step 6: Create Response message with payload containing the localPublicKey
		logger.Debug("\nHandshake-Dialer\nStep 6: Creating response\n")
		localKeyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to marshal local key!\n", err, "\n")
			return err
		}

		response, err := s.sessionCipher.Encrypt(localKeyM)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt local key!\n", err, "\n")
			return err
		}

		// Step 7: Send Response Message
		logger.Debug("\nHandshake-Dialer\nStep 7: Sending response Message\n")
		i, err = s.writeMsgInsecure(response.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")

	} else {

		// Step 0: Preparations
		logger.Debug("\nHandshake-Listener\nStep 0: Preparations\n")
		remoteAddr := protocol.NewSignalAddress("dialer", 2)

		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: Read init. Message and process it
		logger.Debug("\nHandshake-Listener\nStep 1: Reading initial Message\n")
		i, err := s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nRead ", i, " bytes\n")

		receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().PreKeySignalMessage, serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to make prekeymessage from bytes!\n", err, "\n")
			return err
		}

		unsignedPreKeyID, err := s.sessionBuilder.Process(receivedMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to process receivedmessage!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nHeres the retrieved prekey id: ", unsignedPreKeyID, "; dunoo what do with this lol!\n")

		// Step 2: Create SessionCipher and decrypt init. message
		logger.Debug("\nHandshake-Listener\nStep 2: Create sessioncipher\n")
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		msg, err := s.sessionCipher.Decrypt(receivedMessage.WhisperMessage())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to decrypt prekeysignal!\n", err, "\n")
			return err
		}

		logger.Debug("\nHandshake-Listener\nDecryption result: ", msg, "\n")

		// Step 3: Create Response message with payload containing the localPublicKey
		logger.Debug("\nHandshake-Listener\nStep 3: Creating response\n")
		localKeyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to marshal local key!\n", err, "\n")
			return err
		}

		response, err := s.sessionCipher.Encrypt(localKeyM)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to encrypt local key!\n", err, "\n")
			return err
		}

		// Step 4: Send Response Message
		logger.Debug("\nHandshake-Listener\nStep 4: Sending response Message\n")
		i, err = s.writeMsgInsecure(response.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to write message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nWrote ", i, " bytes\n")

		// Step 5: Read Response Message and use payload as remote key
		logger.Debug("\nHandshake-Listener\nStep 5: Receive Response Message and use payload as remote key\n")
		i, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nRead ", i, " bytes\n")

		receivedResponse, err := protocol.NewSignalMessageFromBytes(hbuf, serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to make message from bytes!\n", err, "\n")
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(receivedResponse)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to decrypt message!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to make pubkey!\n", err, "\n")
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to make id from Key!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id
	}

	if s.initiator {
		logger.Debug("\nHandshake-Dialer\nFinished Handshake without errors!\n")
	} else {
		logger.Debug("\nHandshake-Listener\nFinished Handshake without errors!\n")
	}

	logger.Debug("\n\nHandshake exit data:\ninitiator: ", s.initiator,
		"\nLocalAddr: ", s.insecureConn.LocalAddr().String(),
		"\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(),
		"\nNetworkName: ", s.insecureConn.LocalAddr().Network(),
		"\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), ")",
		"\nLocalPeer: ", s.LocalPeer(),
		"\nRemotePeer: ", s.RemotePeer(),
		"\nLocalPrivKey: ", s.LocalPrivateKey(),
		"\nRemotePubKey: ", s.RemotePublicKey(), "\n\n\n")

	return nil
}

/* func (s *signalSession) Handshake(ctx context.Context) (err error) {

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
*/
