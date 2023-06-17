package tonconnect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	"github.com/superseriousbusiness/gotosocial/internal/config"
	"github.com/superseriousbusiness/gotosocial/internal/db"
	"github.com/superseriousbusiness/gotosocial/internal/log"
)

type Domain struct {
	LengthBytes uint32 `json:"lengthBytes"`
	Value       string `json:"value"`
}

type MessageInfo struct {
	Timestamp int64  `json:"timestamp"`
	Domain    Domain `json:"domain"`
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
	StateInit string `json:"state_init"`
}

type TonProof struct {
	Address string      `json:"address"`
	Network string      `json:"network"`
	Proof   MessageInfo `json:"proof"`
}

type HttpRes struct {
	Message    string `json:"message,omitempty" example:"status ok"`
	StatusCode int    `json:"statusCode,omitempty" example:"200"`
}

type ParsedMessage struct {
	Workchain int32
	Address   []byte
	Timstamp  int64
	Domain    Domain
	Signature []byte
	Payload   string
	StateInit string
}

func HttpResErrorWithLog(errMsg string, statusCode int, log *log.Entry) (int, HttpRes) {
	if log != nil {
		log.Error(errMsg)
	}
	return statusCode, HttpRes{
		Message:    errMsg,
		StatusCode: statusCode,
	}
}

type jwtCustomClaims struct {
	Address string `json:"address"`
	jwt.StandardClaims
}

// SignInGETHandler should be served at https://example.org/auth/sign_in.
// The idea is to present a sign in page to the user, where they can enter their username and password.
// The form will then POST to the sign in page, which will be handled by SignInPOSTHandler.
// If an idp provider is set, then the user will be redirected to that to do their sign in.
func (m *Module) GeneratePayloadPOSTHandler(c *gin.Context) {
	log := log.WithField("prefix", "PayloadHandler")

	nonce, err := GenerateNonce()
	if err != nil {
		c.JSON(HttpResErrorWithLog(err.Error(), http.StatusBadRequest, &log))
	}
	endTime := time.Now().Add(time.Duration(config.GetTonproofPayloadLifeTimeSec()) * time.Second)
	sign := base64.RawURLEncoding.EncodeToString(ed25519.Sign(m.priv, []byte(nonce)))
	m.mux.Lock()
	m.payload[nonce] = Payload{
		ExpirtionTime: endTime.Unix(),
		Signature:     sign,
	}
	m.mux.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"payload": nonce,
	})
}

func (m *Module) CheckProofPOSTHandler(c *gin.Context) {
	ctx := c.Request.Context()
	log := log.WithField("prefix", "ProofHandler")
	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(HttpResErrorWithLog(err.Error(), http.StatusBadRequest, &log))

		return
	}
	var tp TonProof
	err = json.Unmarshal(b, &tp)
	if err != nil {
		c.JSON(HttpResErrorWithLog(err.Error(), http.StatusBadRequest, &log))

		return
	}

	// check payload
	m.mux.RLock()
	pl, ok := m.payload[tp.Proof.Payload]
	m.mux.RUnlock()
	if !ok {
		c.JSON(HttpResErrorWithLog("invalid or expired payload", http.StatusBadRequest, &log))

		return
	}
	if time.Now().Unix() > pl.ExpirtionTime {
		c.JSON(HttpResErrorWithLog("payload has been expired", http.StatusBadRequest, &log))

		return
	}
	sign, err := base64.RawURLEncoding.DecodeString(pl.Signature)
	if err != nil {
		c.JSON(HttpResErrorWithLog("can't verify payload signature", http.StatusBadRequest, &log))

		return
	}
	if !ed25519.Verify(m.pub, []byte(tp.Proof.Payload), sign) {
		c.JSON(HttpResErrorWithLog("payload verification failed", http.StatusBadRequest, &log))

		return
	}

	parsed, err := ConvertTonProofMessage(ctx, &tp)
	if err != nil {
		c.JSON(HttpResErrorWithLog(err.Error(), http.StatusBadRequest, &log))

		return
	}

	net := ""
	switch tp.Network {
	case "-3": // testnet network
		net = config.GetTonAPITestNetURI()
	case "-239": // mainnet network
		net = config.GetTonAPIMainNetURI()
	default:
		c.JSON(HttpResErrorWithLog(fmt.Sprintf("undefined network: %v", tp.Network), http.StatusBadRequest, &log))

		return
	}

	check, err := CheckProof(ctx, tp.Address, net, parsed)
	if err != nil {
		c.JSON(HttpResErrorWithLog("proof checking error: "+err.Error(), http.StatusBadRequest, &log))

		return
	}
	if !check {
		c.JSON(HttpResErrorWithLog("proof verification failed", http.StatusBadRequest, &log))

		return
	}

	_, err = m.db.GetUserByTonAddressAndWorkchain(ctx, parsed.Address, parsed.Workchain)

	if err == db.ErrNoEntries {
		//create user
	} else if err != nil {
		c.JSON(HttpResErrorWithLog("failed to authenticate user", http.StatusBadRequest, &log))

		return
	}

	//return a token for a curent user

	c.JSON(http.StatusOK, gin.H{
		"status": "proved",
	})
}

const (
	tonProofPrefix   = "ton-proof-item-v2/"
	tonConnectPrefix = "ton-connect"
)

func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func ConvertTonProofMessage(ctx context.Context, tp *TonProof) (*ParsedMessage, error) {
	log := log.WithField("prefix", "ConverTonProofMessage")

	addr := strings.Split(tp.Address, ":")
	if len(addr) != 2 {
		return nil, fmt.Errorf("invalid address param: %v", tp.Address)
	}

	var parsedMessage ParsedMessage

	workchain, err := strconv.ParseInt(addr[0], 10, 32)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	walletAddr, err := hex.DecodeString(addr[1])
	if err != nil {
		log.Error(err)
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(tp.Proof.Signature)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	parsedMessage.Workchain = int32(workchain)
	parsedMessage.Address = walletAddr
	parsedMessage.Domain = tp.Proof.Domain
	parsedMessage.Timstamp = tp.Proof.Timestamp
	parsedMessage.Signature = sig
	parsedMessage.Payload = tp.Proof.Payload
	parsedMessage.StateInit = tp.Proof.StateInit
	return &parsedMessage, nil
}

func SignatureVerify(pubkey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pubkey, message, signature)
}

func CheckProof(ctx context.Context, address, net string, tonProofReq *ParsedMessage) (bool, error) {
	log := log.WithField("prefix", "CheckProof")
	pubKey, err := GetWalletPubKey(ctx, address, net)
	if err != nil {
		if tonProofReq.StateInit == "" {
			log.Errorf("get wallet address error: %v", err)
			return false, err
		}

		pubKey, err = ParseStateInit(tonProofReq.StateInit)
		if err != nil {
			log.Errorf("parse wallet state init error: %v", err)
			return false, err
		}
	}

	if time.Now().After(time.Unix(tonProofReq.Timstamp, 0).Add(time.Duration(config.GetTonproofLifeTimeSec()) * time.Second)) {
		msgErr := "proof has been expired"
		log.Error(msgErr)
		return false, fmt.Errorf(msgErr)
	}

	if tonProofReq.Domain.Value != config.GetTonproofExampleDomain() {
		msgErr := fmt.Sprintf("wrong domain: %v", tonProofReq.Domain)
		log.Error(msgErr)
		return false, fmt.Errorf(msgErr)
	}

	mes, err := CreateMessage(ctx, tonProofReq)
	if err != nil {
		log.Errorf("create message error: %v", err)
		return false, err
	}

	return SignatureVerify(pubKey, mes, tonProofReq.Signature), nil
}

func CreateMessage(ctx context.Context, message *ParsedMessage) ([]byte, error) {
	wc := make([]byte, 4)
	binary.BigEndian.PutUint32(wc, uint32(message.Workchain))

	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(message.Timstamp))

	dl := make([]byte, 4)
	binary.LittleEndian.PutUint32(dl, message.Domain.LengthBytes)
	m := []byte(tonProofPrefix)
	m = append(m, wc...)
	m = append(m, message.Address...)
	m = append(m, dl...)
	m = append(m, []byte(message.Domain.Value)...)
	m = append(m, ts...)
	m = append(m, []byte(message.Payload)...)
	log.Info(string(m))
	messageHash := sha256.Sum256(m)
	fullMes := []byte{0xff, 0xff}
	fullMes = append(fullMes, []byte(tonConnectPrefix)...)
	fullMes = append(fullMes, messageHash[:]...)
	res := sha256.Sum256(fullMes)
	log.Info(hex.EncodeToString(res[:]))
	return res[:], nil
}
