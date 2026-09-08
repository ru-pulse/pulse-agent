// Package identity stores the agent's Ed25519 keypair and the control-plane
// key it pinned on first contact.
//
// Everything lives under the invoking user's home directory: the agent never
// needs root or Administrator to install, run, or persist its identity.
package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ru-pulse/pulse-agent/internal/protocol"
)

type File struct {
	AgentID            string `json:"agentId"`
	PublicKeyPEM       string `json:"publicKeyPem"`
	PrivateKeyPEM      string `json:"privateKeyPem"`
	PinnedServerKeyPEM string `json:"pinnedServerPubkeyPem"`
}

type Identity struct {
	File       File
	Path       string
	PrivateKey ed25519.PrivateKey
	ServerKey  ed25519.PublicKey
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pulse-agent", "identity.json"), nil
}

// LoadOrCreate returns the existing identity, or generates a fresh keypair on
// first run. The private key never leaves this file.
func LoadOrCreate(path string) (*Identity, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var file File
		if err := json.Unmarshal(raw, &file); err != nil {
			return nil, fmt.Errorf("identity file %s is corrupt: %w", path, err)
		}
		priv, err := protocol.ParsePrivateKeyPEM(file.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("identity file %s has an unusable private key: %w", path, err)
		}
		id := &Identity{File: file, Path: path, PrivateKey: priv}
		if file.PinnedServerKeyPEM != "" {
			serverKey, err := protocol.ParsePublicKeyPEM(file.PinnedServerKeyPEM)
			if err != nil {
				return nil, fmt.Errorf("pinned server key is unusable: %w", err)
			}
			id.ServerKey = serverKey
		}
		return id, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	pub, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubPEM, err := protocol.MarshalPublicKeyPEM(pub)
	if err != nil {
		return nil, err
	}
	privPEM, err := protocol.MarshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}

	id := &Identity{
		File:       File{PublicKeyPEM: pubPEM, PrivateKeyPEM: privPEM},
		Path:       path,
		PrivateKey: priv,
	}
	if err := id.Save(); err != nil {
		return nil, err
	}
	return id, nil
}

func (i *Identity) Save() error {
	if err := os.MkdirAll(filepath.Dir(i.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(i.File, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(i.Path, data, 0o600)
}

// PinServerKey records the control-plane key on first registration. Trust on
// first use: after this, a different key means something changed that the
// partner did not agree to, and the agent refuses to run.
func (i *Identity) PinServerKey(pemStr string) error {
	key, err := protocol.ParsePublicKeyPEM(pemStr)
	if err != nil {
		return err
	}
	i.File.PinnedServerKeyPEM = pemStr
	i.ServerKey = key
	return i.Save()
}

func (i *Identity) IsRegistered() bool {
	return i.File.AgentID != "" && i.File.PinnedServerKeyPEM != ""
}
