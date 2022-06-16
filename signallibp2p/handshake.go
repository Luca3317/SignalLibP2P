package signallibp2p

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
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
const payloadPrefix = "signal-libp2p-static-key:"

/*	2-Message Handshake (appears to work fully)
	TODO
	- Maybe hardcode values retrieved from drive right now
	- Rarely, seemingly random mac mismatch error (occurs after multiple r/ws though)

	Steps
	1. Dialer retrieves Prekey Bundle from "Server" (local drive)
	2. Dialer processes bundle
	3. Dialer sends encrypted PreKeySignalMessage; payload is local public key and signature
	4. Listener receives and processes the PreKeySignalMessage
	5. Listener decrypts message and saves the remote public key
	6. Listener sends encrypted SignalMessage; payload is local public key and signature
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

		remoteAddr := protocol.NewSignalAddress("listener", retr.Ids.DevID)
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

		// Step 3: Create SessionCipher and encrypt payload containing public key as well as signature
		s.sessionCipher = session.NewCipher(&s.sessionBuilder, remoteAddr)

		payload, err := s.generatePublicKeyPayload()
		if err != nil {
			return err
		}

		message, err := s.sessionCipher.Encrypt(payload)
		if err != nil {
			return err
		}

		f, err := os.OpenFile("len", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if _, err := f.WriteString(strconv.Itoa(len(payload)) + ":" + strconv.Itoa(len(message.Serialize())) + "\n"); err != nil {
			panic(err)
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

		err = s.handlePublicKeyPayload(deResponse)
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

		err = s.handlePublicKeyPayload(deMsg)
		if err != nil {
			return err
		}

		// Step 3: Send Response Message, payload containing own public key
		payload, err := s.generatePublicKeyPayload()
		if err != nil {
			return err
		}

		response, err := s.sessionCipher.Encrypt(payload)
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

func (s *signalSession) generatePublicKeyPayload() ([]byte, error) {
	plaintextKey, err := crypto.MarshalPublicKey(s.LocalPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	if len(plaintextKey) != 299 {
		return nil, errors.New("plaintextKey was not 299 bytes long!")
	}

	toSign := append([]byte(payloadPrefix), plaintextKey...)
	signed, err := s.localKey.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign key %w:", err)
	}

	payload := append(plaintextKey, signed...)
	return payload, nil
}

func (s *signalSession) handlePublicKeyPayload(payload []byte) error {
	remoteKeySerialized := payload[:299]
	remoteKey, err := crypto.UnmarshalPublicKey(remoteKeySerialized)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	id, err := peer.IDFromPublicKey(remoteKey)
	if err != nil {
		return err
	}

	// copied from noise
	// check the peer ID for:
	// * all outbound connection
	// * inbound connections, if we know which peer we want to connect to (SecureInbound called with a peer ID)
	if (s.initiator && s.remoteID != id) || (!s.initiator && s.remoteID != "" && s.remoteID != id) {
		// use Pretty() as it produces the full b58-encoded string, rather than abbreviated forms.
		return fmt.Errorf("peer id mismatch: expected %s, but remote key matches %s", s.remoteID.Pretty(), id.Pretty())
	}

	msg := append([]byte(payloadPrefix), remoteKeySerialized...)
	ok, err := remoteKey.Verify(msg, payload[299:])
	if err != nil {
		return fmt.Errorf("failed to verify remotekey: %w", err)
	} else if !ok {
		return errors.New("remote signature of public key invalid!")
	}

	s.remoteKey = remoteKey
	s.remoteID = id
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
