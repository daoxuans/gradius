package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"gradius/internal/accounting"
	"gradius/internal/admin"
	"gradius/internal/auth"
	"gradius/internal/logger"
	"gradius/internal/metrics"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

type Server struct {
	secret        string
	authenticator *auth.RedisAuthenticator
	accounter     accounting.Accounter
	nasValidator  *auth.NASIPValidator
	metrics       *metrics.Metrics
	adminServer   *admin.AdminServer
	authServer    *radius.PacketServer
	acctServer    *radius.PacketServer
	log           *logrus.Logger
}

func NewServer(secret string, authenticator *auth.RedisAuthenticator, accounter accounting.Accounter, nasValidator *auth.NASIPValidator) *Server {
	metrics := metrics.New()
	s := &Server{
		secret:        secret,
		authenticator: authenticator,
		accounter:     accounter,
		nasValidator:  nasValidator,
		metrics:       metrics,
		adminServer:   nil,
		authServer:    nil,
		acctServer:    nil,
		log:           logger.GetLogger(),
	}

	return s
}

func generateMessageAuthenticator(p *radius.Packet, secret string) []byte {
	b, _ := p.MarshalBinary()
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(b)
	authenticator := mac.Sum(nil)
	return authenticator
}

func sendAuthResponse(w radius.ResponseWriter, r *radius.Request, code radius.Code, secret string) {
	resp := r.Response(code)
	rfc2869.MessageAuthenticator_Set(resp, make([]byte, 16))
	authenticator := generateMessageAuthenticator(resp, secret)
	rfc2869.MessageAuthenticator_Set(resp, authenticator)
	w.Write(resp)
}
func (s *Server) handlePacket(w radius.ResponseWriter, r *radius.Request) {
	nasIP := rfc2865.NASIPAddress_Get(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"code":   r.Code.String(),
		"client": r.RemoteAddr.String(),
		"nas_ip": nasIP,
	})

	if !s.nasValidator.IsAllowed(nasIP) {
		logger.Warn("Unauthorized NAS IP address")
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if rfc2865.UserName_GetString(r.Packet) == "" {
		logger.Warn("Missing User-Name attribute")
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// if rfc2869.MessageAuthenticator_Get(r.Packet) == nil {
	// 	logger.Warn("Missing Message-Authenticator attribute")
	// 	w.Write(r.Response(radius.CodeAccessReject))
	// 	return
	// }

	switch r.Code {
	case radius.CodeAccessRequest:
		s.handleAccessRequest(w, r)
	case radius.CodeAccountingRequest:
		s.handleAccountingRequest(w, r)
	default:
		logger.Warn("Unsupported RADIUS packet type")
		w.Write(r.Response(radius.CodeAccessReject))
	}
}

func (s *Server) handleAccessRequest(w radius.ResponseWriter, r *radius.Request) {
	start := time.Now()

	username := rfc2865.UserName_GetString(r.Packet)
	nasip := rfc2865.NASIPAddress_Get(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"username": username,
		"nas":      nasip.String(),
	})

	var valid bool
	var err error

	// Check if this is a MAC authentication request
	callingStationID := rfc2865.CallingStationID_GetString(r.Packet)
	MacAddr := strings.ReplaceAll(callingStationID, "-", ":")
	if MacAddr == username {
		logger = logger.WithField("mac", MacAddr)
		logger.Info("Processing MAC authentication")
		valid, err = s.authenticator.ValidateMAC(MacAddr)
	} else if chapChallenge := rfc2865.CHAPChallenge_Get(r.Packet); chapChallenge != nil {
		// CHAP authentication
		logger.Info("Processing CHAP authentication")
		chapPassword := rfc2865.CHAPPassword_Get(r.Packet)
		if chapPassword == nil {
			logger.Warn("Missing CHAP password")
			s.metrics.RecordAuthRequest(false, time.Since(start))
			sendAuthResponse(w, r, radius.CodeAccessReject, s.secret)
			return
		}
		valid, err = s.authenticator.ValidateCredentials(username, "", auth.CHAP, chapChallenge, chapPassword)
	} else {
		// PAP authentication
		logger.Info("Processing PAP authentication")
		password := rfc2865.UserPassword_GetString(r.Packet)
		valid, err = s.authenticator.ValidateCredentials(username, password, auth.PAP, nil, nil)
	}

	if err != nil {
		logger.WithError(err).Error("Authentication error")
		s.metrics.RecordAuthRequest(false, time.Since(start))
		sendAuthResponse(w, r, radius.CodeAccessReject, s.secret)
		return
	}

	if valid {
		logger.Info("Authentication successful")
		s.metrics.RecordAuthRequest(true, time.Since(start))
		sendAuthResponse(w, r, radius.CodeAccessAccept, s.secret)
	} else {
		logger.Info("Authentication failed")
		s.metrics.RecordAuthRequest(false, time.Since(start))
		sendAuthResponse(w, r, radius.CodeAccessReject, s.secret)
	}
}

func (s *Server) handleAccountingRequest(w radius.ResponseWriter, r *radius.Request) {
	start := time.Now()

	nasIPAddr := rfc2865.NASIPAddress_Get(r.Packet).String()
	username := rfc2865.UserName_GetString(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"username": username,
		"nas":      nasIPAddr,
	})

	sessionID := rfc2866.AcctSessionID_GetString(r.Packet)
	acctStatusType := rfc2866.AcctStatusType_Get(r.Packet)

	framedIPAddr := rfc2865.FramedIPAddress_Get(r.Packet).String()
	callingStationID := rfc2865.CallingStationID_GetString(r.Packet)
	calledStationID := rfc2865.CalledStationID_GetString(r.Packet)
	nasPort := int(rfc2865.NASPort_Get(r.Packet))
	nasPortType := rfc2865.NASPortType_Get(r.Packet).String()
	nasIdentifier := rfc2865.NASIdentifier_GetString(r.Packet)

	now := time.Now().UTC()
	timestamp := now.Unix()
	eventTimestamp := now.Format(time.RFC3339)

	var eventType string
	switch acctStatusType {
	case rfc2866.AcctStatusType_Value_Start:
		logger.Info("Processing start accounting request")
		eventType = "Start"
	case rfc2866.AcctStatusType_Value_Stop:
		logger.Info("Processing stop accounting request")
		eventType = "Stop"
	case rfc2866.AcctStatusType_Value_InterimUpdate:
		logger.Info("Processing interim accounting update")
		eventType = "Interim-Update"
	default:
		logger.Warn("Unknown accounting status type")
		eventType = "Unknown"
	}

	acctData := &accounting.AccountingData{
		EventType:        eventType,
		Timestamp:        timestamp,
		EventTimestamp:   eventTimestamp,
		UserName:         username,
		NasIdentifier:    nasIdentifier,
		NASIPAddr:        nasIPAddr,
		AcctSessionID:    sessionID,
		FramedIP:         framedIPAddr,
		CallingStationID: callingStationID,
		CalledStationID:  calledStationID,
		NasPort:          nasPort,
		NasPortType:      nasPortType,
	}

	if err := s.accounter.SendAccountingData(acctData); err != nil {
		logger.WithError(err).Error("Failed to send accounting data")
		s.metrics.RecordAcctRequest(false, time.Since(start))
	} else {
		s.metrics.RecordAcctRequest(true, time.Since(start))
	}

	// Always respond with success as per RFC 2866
	w.Write(r.Response(radius.CodeAccountingResponse))
}

func (s *Server) ListenAndServe(authAddr, acctAddr, adminAddr string) error {
	errChan := make(chan error, 3)

	s.authServer = &radius.PacketServer{
		Addr:         authAddr,
		SecretSource: radius.StaticSecretSource([]byte(s.secret)),
		Handler:      radius.HandlerFunc(s.handlePacket),
	}
	go func() {
		if err := s.authServer.ListenAndServe(); err != nil {
			if err == radius.ErrServerShutdown {
				return
			}
			s.log.WithError(err).Error("Authentication server error")
			errChan <- fmt.Errorf("authentication server error: %w", err)
		}
	}()

	s.acctServer = &radius.PacketServer{
		Addr:         acctAddr,
		SecretSource: radius.StaticSecretSource([]byte(s.secret)),
		Handler:      radius.HandlerFunc(s.handlePacket),
	}
	go func() {
		if err := s.acctServer.ListenAndServe(); err != nil {
			if err == radius.ErrServerShutdown {
				return
			}
			s.log.WithError(err).Error("Accounting server error")
			errChan <- fmt.Errorf("accounting server error: %w", err)
		}
	}()

	s.adminServer = admin.NewAdminServer(s.metrics, adminAddr)
	go func() {
		if err := s.adminServer.Start(); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			s.log.WithError(err).Error("Admin server error")
			errChan <- fmt.Errorf("admin server error: %w", err)
		}
	}()

	return <-errChan
}

func (s *Server) Shutdown() error {
	var errs []error

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.authenticator.Close(); err != nil {
		errs = append(errs, fmt.Errorf("error closing authenticator: %w", err))
	} else {
		s.log.Info("Release authenticator")
	}

	if err := s.accounter.Close(); err != nil {
		errs = append(errs, fmt.Errorf("error closing accounter: %w", err))
	} else {
		s.log.Info("Release accounter")
	}

	if err := s.adminServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down admin server: %w", err))
	} else {
		s.log.Info("Closed admin server")
	}

	if err := s.acctServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down acct server: %w", err))
	} else {
		s.log.Info("Closed acct server")
	}
	if err := s.authServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down auth server: %w", err))
	} else {
		s.log.Info("Closed auth server")
	}
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}
