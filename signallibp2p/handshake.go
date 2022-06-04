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

		// Step 5: Receive response; use payload as remote key
		logger.Debug("\nHandshake-Dialer\nStep 5: Receive Response\n")
		i, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nRead ", i, " bytes\n")

		response, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make signal message from bytes!\n", err, "\n")
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(response)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to decrypt response!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make pubkey from bytes!\n", err, "\n")
			return err
		}
		logger.Debug("\nTHE KEY:\n", pubkey, "\n")

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make id!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id

		// Step 6: Send Response Message
		logger.Debug("\nHandshake-Dialer\nStep 5: Send Response with localkey as payload\n")

		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to marshal localkey!\n", err, "\n")
			return err
		}

		ack, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt localkey!\n", err, "\n")
			return err
		}

		i, err = s.writeMsgInsecure(ack.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write localkey!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")
		logger.Debug("\nTHE KEY:\n", keyM, "\n")

		/* 		logger.Debug("Im leaving my handshake\n")
		   		logger.Debug("First receiving test message\n")
		   		var mybuf []byte
		   		i, err = s.Read(mybuf)
		   		if err != nil {
		   			logger.Debug("I failed to read for some reason \n")
		   			logger.Debug(err)
		   		} else {
		   			logger.Debug("Did it !\n", string(mybuf), "\n")
		   		} */

	} else {

		// Step 0: Preparations
		logger.Debug("\nHandshake-Listener\nStep 0: Preparation\n")
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

		logger.Debug("\nHandshake-Listener\nDecryption result: ", string(msg), "\n")

		// Step 3: Send Response Message
		logger.Debug("\nHandshake-Listener\nStep 3: Send Response with localkey as payload\n")

		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to marshal localkey!\n", err, "\n")
			return err
		}

		response, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to encrypt localkey!\n", err, "\n")
			return err
		}

		i, err = s.writeMsgInsecure(response.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to write localkey!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nWrote ", i, " bytes\n")
		logger.Debug("\nTHE KEY:\n", keyM, "\n")

		// Step 5: Receive response; use payload as remote key
		logger.Debug("\nHandshake-Dialer\nStep 5: Receiving ACK\n")
		i, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nRead ", i, " bytes\n")

		ack, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make signal message from bytes!\n", err, "\n")
			return err
		}

		deAck, err := s.sessionCipher.Decrypt(ack)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to decrypt response!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deAck)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make pubkey from bytes!\n", err, "\n")
			return err
		}
		logger.Debug("\nTHE KEY:\n", pubkey, "\n")

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make id!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id

		/* 		logger.Debug("Im leaving my handshake\n")
		   		logger.Debug("First sending test message\n")
		   		i, err = s.Write(append([]byte("My test message... wwhats up"), 0))
		   		if err != nil {
		   			logger.Debug("I failed to write for some reason\n")
		   			logger.Debug(err)
		   		} else {
		   			logger.Debug("Did it !\n")
		   		} */
	}

	logger.Debug("\nFinished Handshake\n\nExit data:\ninitiator: ", s.initiator,
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

/*
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

		// Step 5: Receive response; use payload as remote key
		logger.Debug("\nHandshake-Dialer\nStep 5: Receive Response\n")
		i, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nRead ", i, " bytes\n")

		response, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make signal message from bytes!\n", err, "\n")
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(response)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to decrypt response!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make pubkey from bytes!\n", err, "\n")
			return err
		}
		logger.Debug("\nTHE KEY:\n", pubkey, "\n")

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make id!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id

		// Step 6: Send Response Message
		logger.Debug("\nHandshake-Dialer\nStep 5: Send Response with localkey as payload\n")

		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to marshal localkey!\n", err, "\n")
			return err
		}

		ack, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to encrypt localkey!\n", err, "\n")
			return err
		}

		i, err = s.writeMsgInsecure(ack.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to write localkey!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nWrote ", i, " bytes\n")
		logger.Debug("\nTHE KEY:\n", keyM, "\n")

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

		logger.Debug("\nHandshake-Listener\nDecryption result: ", string(msg), "\n")

		// Step 3: Send Response Message
		logger.Debug("\nHandshake-Listener\nStep 3: Send Response with localkey as payload\n")

		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to marshal localkey!\n", err, "\n")
			return err
		}

		response, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to encrypt localkey!\n", err, "\n")
			return err
		}

		i, err = s.writeMsgInsecure(response.Serialize())
		if err != nil {
			logger.Debug("\nHandshake-Listener\nReturning; Failed to write localkey!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Listener\nWrote ", i, " bytes\n")
		logger.Debug("\nTHE KEY:\n", keyM, "\n")

		// Step 5: Receive response; use payload as remote key
		logger.Debug("\nHandshake-Dialer\nStep 5: Receiving ACK\n")
		i, err = s.insecureConn.Read(hbuf)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to read message!\n", err, "\n")
			return err
		}
		logger.Debug("\nHandshake-Dialer\nRead ", i, " bytes\n")

		ack, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make signal message from bytes!\n", err, "\n")
			return err
		}

		deAck, err := s.sessionCipher.Decrypt(ack)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to decrypt response!\n", err, "\n")
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deAck)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make pubkey from bytes!\n", err, "\n")
			return err
		}
		logger.Debug("\nTHE KEY:\n", pubkey, "\n")

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			logger.Debug("\nHandshake-Dialer\nReturning; Failed to make id!\n", err, "\n")
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id
	}

	logger.Debug("\nFinished Handshake\n\nExit data:\ninitiator: ", s.initiator,
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

*/
