package signallibp2p

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
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

/*	2-Message Handshake (appears to work fully)
	TODO
	- Test this more
	- Maybe add length prefixes to messages sent here as well
	- Maybe hardcode values retrieved from drive right now
	- Very rarely, seemingly random mac mismatch error (fixed?)

	Steps
	1. Dialer retrieves Prekey Bundle from "Server" (local drive)
	2. Dialer processes bundle
	3. Dialer sends encrypted PreKeySignalMessage; payload is their local public key
	4. Listener receives and processes the PreKeySignalMessage
	5. Listener decrypts message and saves the remote public key
	6. Listener sends encrypted SignalMessage; payload is their local public key
	7. Dialer receives and decrypts message, saves the remote public key
	8. Handshake is finished
*/
func (s *signalSession) handshake(ctx context.Context) (err error) {

	/* logger.Debug("\n\nHandshake enter data:\ninitiator: ", s.initiator,
	"\nLocalAddr: ", s.insecureConn.LocalAddr().String(),
	"\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(),
	"\nNetworkName: ", s.insecureConn.LocalAddr().Network(),
	"\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), ")",
	"\nLocalPeer: ", s.LocalPeer(),
	"\nRemotePeer: ", s.RemotePeer(),
	"\nLocalPrivKey: ", s.LocalPrivateKey(),
	"\nRemotePubKey: ", s.RemotePublicKey(), "\n\n\n") */

	defer func() {
		if rerr := recover(); rerr != nil {
			fmt.Fprintf(os.Stderr, "caught panic: %s\n%s\n", rerr, debug.Stack())
			err = fmt.Errorf("panic in Signal handshake: %s", rerr)
		}
	}()

	// Set a deadline to complete the handshake, if one has been supplied.
	// Clear it after we're done.
	if deadline, ok := ctx.Deadline(); ok {
		if err := s.SetDeadline(deadline); err == nil {
			// schedule the deadline removal once we're done handshaking.
			defer s.SetDeadline(time.Time{})
		}
	}

	hbuf := pool.Get(buffersize)
	defer pool.Put(hbuf)

	// If this is the initiator
	if s.initiator {

		// Step 0: Preparations (including ReadBundle and session.NewBuilder)
		retr, err := retrievable.ReadBundle()
		if err != nil {
			return errors.New("Failed to read bundle:" + err.Error())
		}

		remoteAddr := protocol.NewSignalAddress("listener", 1)
		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: "Retrieve Bundle from server"
		retrievedBundle := prekey.NewBundle(
			retr.Ids.RegID, retr.Ids.DevID,
			retr.PreKey.ID(), retr.SignedPreKey.ID(),
			retr.PreKey.KeyPair().PublicKey(), retr.SignedPreKey.KeyPair().PublicKey(),
			retr.SignedPreKey.Signature(),
			retr.IdentityKeyPair.PublicKey(),
		)

		// Step 2: Process retrieved Bundle
		err = s.sessionBuilder.ProcessBundle(retrievedBundle)
		if err != nil {
			return err
		}

		// Step 3: Create SessionCipher and encrypt message containing the local public key
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		plaintextKey, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			return err
		}

		message, err := s.sessionCipher.Encrypt(plaintextKey)
		if err != nil {
			return err
		}

		// Step 4: Send (initiating) message
		_, err = s.writeMsgInsecure(s.prependLength(message.Serialize()))
		if err != nil {
			return err
		}

		// Step 5: Receive response; use payload as remote key
		msglen, err := s.readNextInsecureMsgLen()
		if err != nil {
			return err
		}

		err = s.readNextMsgInsecure(hbuf[:msglen])
		if err != nil {
			return err
		}

		response, err := protocol.NewSignalMessageFromBytes(hbuf[:msglen], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(response)
		if err != nil {
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			return err
		}

		s.remoteKey = pubkey
		if s.remoteID != id {
			return errors.New("Handshake: remote id mismatch")
		}

	} else {

		// Step 0: Preparations
		remoteAddr := protocol.NewSignalAddress("dialer", 2)

		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: Read init. Message and process it
		msglen, err := s.readNextInsecureMsgLen()
		if err != nil {
			return err
		}

		err = s.readNextMsgInsecure(hbuf[:msglen])
		if err != nil {
			return err
		}

		receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(hbuf[:msglen], serialize.NewJSONSerializer().PreKeySignalMessage, serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			return err
		}

		_, err = s.sessionBuilder.Process(receivedMessage)
		if err != nil {
			logger.Debug("failed to process")
			return err
		}

		// Step 2: Create SessionCipher and decrypt init. message; use payload as remote public key
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		deMsg, err := s.sessionCipher.Decrypt(receivedMessage.WhisperMessage())
		if err != nil {
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deMsg)
		if err != nil {
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			return err
		}

		s.remoteKey = pubkey
		s.remoteID = id

		// Step 3: Send Response Message, payload containing own public key
		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			return err
		}

		response, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			return err
		}

		_, err = s.writeMsgInsecure(s.prependLength(response.Serialize()))
		if err != nil {
			return err
		}
	}

	/* logger.Debug("\nFinished Handshake\n\nExit data:\ninitiator: ", s.initiator,
	"\nLocalAddr: ", s.insecureConn.LocalAddr().String(),
	"\nRemoteAddr: ", s.insecureConn.RemoteAddr().String(),
	"\nNetworkName: ", s.insecureConn.LocalAddr().Network(),
	"\n(RemoteNetworkName: ", s.insecureConn.RemoteAddr().Network(), ")",
	"\nLocalPeer: ", s.LocalPeer(),
	"\nRemotePeer: ", s.RemotePeer(),
	"\nLocalPrivKey: ", s.LocalPrivateKey(),
	"\nRemotePubKey: ", s.RemotePublicKey(), "\n\n\n") */

	return nil
}

/*
	3 Message Handshake (works fully (i think))
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
		retr, err := retrievable.ReadBundle()
		if err != nil {
			return errors.New("Failed to read bundle:" + err.Error())
		}

		remoteAddr := protocol.NewSignalAddress("listener", 1)
		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: "Retrieve Bundle from server"
		retrievedBundle := prekey.NewBundle(
			retr.Ids.RegID, retr.Ids.DevID,
			retr.PreKey.ID(), retr.SignedPreKey.ID(),
			retr.PreKey.KeyPair().PublicKey(), retr.SignedPreKey.KeyPair().PublicKey(),
			retr.SignedPreKey.Signature(),
			retr.IdentityKeyPair.PublicKey(),
		)

		// Step 2: Process retrieved Bundle
		err = s.sessionBuilder.ProcessBundle(retrievedBundle)
		if err != nil {
			return err
		}

		// Step 3: Create SessionCipher and encrypt init. message
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		plaintext := []byte("Hallo!")
		message, err := s.sessionCipher.Encrypt(plaintext)
		if err != nil {
			return err
		}

		// Step 4: Send init. message
		_, err = s.writeMsgInsecure(message.Serialize())
		if err != nil {
			return err
		}

		// Step 5: Receive response; use payload as remote key
		_, err = s.insecureConn.Read(hbuf)
		if err != nil {
			return err
		}

		response, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			return err
		}

		deResponse, err := s.sessionCipher.Decrypt(response)
		if err != nil {
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deResponse)
		if err != nil {
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
			return err
		}

		s.remoteKey = pubkey
		if s.remoteID != id {
			return errors.New("Handshake: remote id mismatch")
		}

		// Step 6: Send Response Message
		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			return err
		}

		ack, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			return err
		}

		_, err = s.writeMsgInsecure(ack.Serialize())
		if err != nil {
			return err
		}

	} else {

		// Step 0: Preparations
		remoteAddr := protocol.NewSignalAddress("dialer", 2)

		s.sessionBuilder = *session.NewBuilder(
			&s.sessionStore, &s.prekeyStore, &s.signedprekeyStore, &s.identityStore,
			remoteAddr, s.sessionStore.serializer,
		)

		// Step 1: Read init. Message and process it
		_, err := s.insecureConn.Read(hbuf)
		if err != nil {
			return err
		}

		receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().PreKeySignalMessage, serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			return err
		}

		unsignedPreKeyID, err := s.sessionBuilder.Process(receivedMessage)
		if err != nil {
			logger.Debug("failed to process")
			return err
		}
		logger.Debug("Succesfully processed ", unsignedPreKeyID)

		// Step 2: Create SessionCipher and decrypt init. message
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)
		_, err = s.sessionCipher.Decrypt(receivedMessage.WhisperMessage())
		if err != nil {
			return err
		}

		// Step 3: Send Response Message
		keyM, err := crypto.MarshalPublicKey(s.LocalPublicKey())
		if err != nil {
			return err
		}

		response, err := s.sessionCipher.Encrypt(keyM)
		if err != nil {
			return err
		}

		_, err = s.writeMsgInsecure(response.Serialize())
		if err != nil {
			return err
		}

		// Step 5: Receive response; use payload as remote key
		_, err = s.insecureConn.Read(hbuf)
		if err != nil {
			return err
		}

		ack, err := protocol.NewSignalMessageFromBytes(hbuf[:strings.IndexByte(string(hbuf), 0)], serialize.NewJSONSerializer().SignalMessage)
		if err != nil {
			return err
		}

		deAck, err := s.sessionCipher.Decrypt(ack)
		if err != nil {
			return err
		}

		pubkey, err := crypto.UnmarshalPublicKey(deAck)
		if err != nil {
			return err
		}

		id, err := peer.IDFromPublicKey(pubkey)
		if err != nil {
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
