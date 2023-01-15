package tonconnect

import (
	"crypto/ed25519"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type Payload struct {
	ExpirtionTime int64
	Signature     string
}

/* #nosec G101 */
const (
	// TonProofGeneratePayloadPath is the API path for ton connect to get a payload
	TonProofGeneratePayloadPath = "/generatePayload"
	// TonProofCheckProofPath is the API path for ton connect for providing proof
	TonProofCheckProofPath = "/checkProof"
)

type Module struct {
	// db      db.DB
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	payload map[string]Payload
	mux     sync.RWMutex
}

func (m *Module) worker() {
	for {
		<-time.NewTimer(time.Minute).C
		for k, v := range m.payload {
			if time.Now().Unix() > v.ExpirtionTime {
				delete(m.payload, k)
			}
		}
	}
}

// New returns a new tonconnect module
func New(pub ed25519.PublicKey, priv ed25519.PrivateKey) *Module {
	var m = &Module{
		// db:      db,
		pub:     pub,
		priv:    priv,
		payload: make(map[string]Payload),
	}

	go m.worker()

	return m
}

// Route satisfies the RESTAPIModule interface
func (m *Module) Route(attachHandler func(method string, path string, f ...gin.HandlerFunc) gin.IRoutes) {
	attachHandler(http.MethodPost, TonProofGeneratePayloadPath, m.GeneratePayloadPOSTHandler)
	attachHandler(http.MethodPost, TonProofCheckProofPath, m.CheckProofPOSTHandler)
}
