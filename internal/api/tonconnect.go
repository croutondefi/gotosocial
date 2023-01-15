package api

import (
	"crypto/ed25519"

	"github.com/gin-gonic/gin"
	"github.com/superseriousbusiness/gotosocial/internal/api/tonconnect"
	"github.com/superseriousbusiness/gotosocial/internal/router"
)

type TonConnect struct {
	tc *tonconnect.Module
}

// NewTonConnect returns a new tonconnect module
func NewTonConnect(pub ed25519.PublicKey, priv ed25519.PrivateKey) *TonConnect {
	var m = &TonConnect{
		tc: tonconnect.New(pub, priv),
	}

	return m
}

// Route satisfies the RESTAPIModule interface
func (t *TonConnect) Route(r router.Router, m ...gin.HandlerFunc) {
	pGroup := r.AttachGroup("ton-proof")

	pGroup.Use(m...)

	t.tc.Route(pGroup.Handle)
}
