package radius

import (
	"fmt"
	"gradius/internal/accounting"
	"gradius/internal/admin"
	"gradius/internal/auth"
	"gradius/internal/logger"
	"gradius/internal/metrics"
	"time"

	"github.com/sirupsen/logrus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

type Server struct {
	secret        string
	authenticator *auth.RedisAuthenticator
	accounter     *accounting.KafkaAccounter
	nasValidator  *auth.NASIPValidator
	metrics       *metrics.Metrics
	adminServer   *admin.AdminServer
	server        *radius.PacketServer
	log           *logrus.Logger
}

func NewServer(secret string, authenticator *auth.RedisAuthenticator, accounter *accounting.KafkaAccounter, nasValidator *auth.NASIPValidator, adminAddr string) *Server {
	metrics := metrics.New()
	s := &Server{
		secret:        secret,
		authenticator: authenticator,
		accounter:     accounter,
		nasValidator:  nasValidator,
		metrics:       metrics,
		adminServer:   admin.NewAdminServer(metrics, adminAddr),
		log:           logger.GetLogger(),
	}

	s.server = &radius.PacketServer{
		SecretSource: radius.StaticSecretSource([]byte(secret)),
		Handler:      radius.HandlerFunc(s.handlePacket),
	}

	return s
}

func (s *Server) handlePacket(w radius.ResponseWriter, r *radius.Request) {
	nasIP := rfc2865.NASIPAddress_Get(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"code":   r.Code.String(),
		"client": r.RemoteAddr.String(),
		"nas_ip": nasIP,
	})

	// 验证 NAS IP
	if !s.nasValidator.IsAllowed(nasIP) {
		logger.Warn("Unauthorized NAS IP address")
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

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
	s.metrics.IncrementConnections()
	defer s.metrics.DecrementConnections()

	username := rfc2865.UserName_GetString(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"username": username,
		"client":   r.RemoteAddr.String(),
	})

	var valid bool
	var err error

	// Check if this is a MAC authentication request
	if callingStationID := rfc2865.CallingStationID_GetString(r.Packet); callingStationID != "" {
		logger = logger.WithField("mac", callingStationID)
		logger.Info("Processing MAC authentication")
		valid, err = s.authenticator.ValidateMAC(callingStationID)
	} else if chapChallenge := rfc2865.CHAPChallenge_Get(r.Packet); chapChallenge != nil {
		// CHAP authentication
		logger.Info("Processing CHAP authentication")
		chapPassword := rfc2865.CHAPPassword_Get(r.Packet)
		if chapPassword == nil {
			logger.Warn("Missing CHAP password")
			s.metrics.RecordAuthRequest(false, time.Since(start))
			w.Write(r.Response(radius.CodeAccessReject))
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
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if valid {
		logger.Info("Authentication successful")
		s.metrics.RecordAuthRequest(true, time.Since(start))
		resp := r.Response(radius.CodeAccessAccept)
		w.Write(resp)
	} else {
		logger.Info("Authentication failed")
		s.metrics.RecordAuthRequest(false, time.Since(start))
		w.Write(r.Response(radius.CodeAccessReject))
	}
}

func (s *Server) handleAccountingRequest(w radius.ResponseWriter, r *radius.Request) {
	start := time.Now()
	s.metrics.IncrementConnections()
	defer s.metrics.DecrementConnections()

	username := rfc2865.UserName_GetString(r.Packet)
	sessionID := rfc2866.AcctSessionID_GetString(r.Packet)
	nasIPAddr := rfc2865.NASIPAddress_Get(r.Packet).String()
	acctStatusType := rfc2866.AcctStatusType_Get(r.Packet)

	logger := s.log.WithFields(logrus.Fields{
		"username":    username,
		"session_id":  sessionID,
		"nas_ip":      nasIPAddr,
		"status_type": acctStatusType,
	})

	acctData := &accounting.AccountingData{
		Username:    username,
		NASIPAddr:   nasIPAddr,
		SessionID:   sessionID,
		BytesIn:     uint32(rfc2866.AcctInputOctets_Get(r.Packet)),
		BytesOut:    uint32(rfc2866.AcctOutputOctets_Get(r.Packet)),
		PacketsIn:   uint32(rfc2866.AcctInputPackets_Get(r.Packet)),
		PacketsOut:  uint32(rfc2866.AcctOutputPackets_Get(r.Packet)),
		SessionTime: int(rfc2866.AcctSessionTime_Get(r.Packet)),
	}

	switch acctStatusType {
	case rfc2866.AcctStatusType_Value_Start:
		logger.Info("Processing start accounting request")
		acctData.StartTime = time.Now()
	case rfc2866.AcctStatusType_Value_Stop:
		logger.Info("Processing stop accounting request")
		acctData.StopTime = time.Now()
	case rfc2866.AcctStatusType_Value_InterimUpdate:
		logger.Info("Processing interim accounting update")
	default:
		logger.Warn("Unknown accounting status type")
	}

	if err := s.accounter.SendAccountingData(acctData); err != nil {
		logger.WithError(err).Error("Failed to send accounting data")
		s.metrics.RecordAcctRequest(false, time.Since(start))
	} else {
		s.metrics.RecordAcctRequest(true, time.Since(start))
	}

	// Always respond with success as per RFC 2866
	resp := r.Response(radius.CodeAccountingResponse)
	w.Write(resp)
}

func (s *Server) ListenAndServe(authAddr, acctAddr string) error {
	errChan := make(chan error, 3) // Now handling 3 servers

	// Start admin server
	go func() {
		if err := s.adminServer.Start(); err != nil {
			s.log.WithError(err).Error("Admin server error")
			errChan <- fmt.Errorf("admin server error: %w", err)
		}
	}()

	// Start authentication server
	authServer := &radius.PacketServer{
		Addr:         authAddr,
		SecretSource: radius.StaticSecretSource([]byte(s.secret)),
		Handler:      radius.HandlerFunc(s.handlePacket),
	}

	// Start accounting server
	acctServer := &radius.PacketServer{
		Addr:         acctAddr,
		SecretSource: radius.StaticSecretSource([]byte(s.secret)),
		Handler:      radius.HandlerFunc(s.handlePacket),
	}

	// Start both RADIUS servers in goroutines
	go func() {
		errChan <- authServer.ListenAndServe()
	}()

	go func() {
		errChan <- acctServer.ListenAndServe()
	}()

	// Return first error encountered
	return <-errChan
}

func (s *Server) Shutdown() error {
	if err := s.authenticator.Close(); err != nil {
		return fmt.Errorf("error closing authenticator: %w", err)
	}

	if err := s.accounter.Close(); err != nil {
		return fmt.Errorf("error closing accounter: %w", err)
	}

	if err := s.adminServer.Stop(); err != nil {
		return fmt.Errorf("error stopping admin server: %w", err)
	}

	return nil
}
