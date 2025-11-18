package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"gradius/internal/admin"
	"gradius/internal/auth"
	"gradius/internal/exporter"
	"gradius/internal/logger"
	"gradius/internal/metrics"
	"net"
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
	exporter      exporter.MessageExporter
	nasValidator  *auth.NASIPValidator
	metrics       *metrics.Metrics
	adminServer   *admin.AdminServer
	authServer    *radius.PacketServer
	acctServer    *radius.PacketServer
	log           *logrus.Logger
}

func NewServer(secret string, authenticator *auth.RedisAuthenticator, exporter exporter.MessageExporter, nasValidator *auth.NASIPValidator) *Server {
	metrics := metrics.New()
	s := &Server{
		secret:        secret,
		authenticator: authenticator,
		exporter:      exporter,
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

func packetSourceIP(r *radius.Request) net.IP {
	if r == nil || r.RemoteAddr == nil {
		return nil
	}
	if addr, ok := r.RemoteAddr.(*net.UDPAddr); ok {
		return addr.IP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func (s *Server) handlePacket(w radius.ResponseWriter, r *radius.Request) {
	nasIP := rfc2865.NASIPAddress_Get(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"code":   r.Code.String(),
		"client": r.RemoteAddr.String(),
		"nas_ip": nasIP.String(),
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

func isMACBasedAuth(packet *radius.Packet) bool {
	if rfc2865.ServiceType_Get(packet) == rfc2865.ServiceType_Value_CallCheck {
		return true
	}

	callingStationID := rfc2865.CallingStationID_GetString(packet)
	username := rfc2865.UserName_GetString(packet)

	normalizedMAC := strings.ReplaceAll(callingStationID, "-", ":")
	return normalizedMAC == username
}

func (s *Server) handleAccessRequest(w radius.ResponseWriter, r *radius.Request) {
	start := time.Now()

	userName := rfc2865.UserName_GetString(r.Packet)
	packetIP := packetSourceIP(r)
	if packetIP == nil || packetIP.IsUnspecified() {
		packetIP = rfc2865.NASIPAddress_Get(r.Packet)
	}
	nasIPStr := packetIP.String()
	logger := s.log.WithFields(logrus.Fields{
		"username": userName,
		"nas":      nasIPStr,
	})

	var valid bool
	var err error

	framedIPAddr := rfc2865.FramedIPAddress_Get(r.Packet).String()
	callingStationID := rfc2865.CallingStationID_GetString(r.Packet)
	calledStationID := rfc2865.CalledStationID_GetString(r.Packet)

	authData := &exporter.AuthingData{
		Timestamp:        time.Now().UTC().Unix(),
		UserName:         userName,
		FramedIP:         framedIPAddr,
		CallingStationID: callingStationID,
		CalledStationID:  calledStationID,
		NASIPAddr:        nasIPStr,
	}

	// Check if this is a MAC authentication request
	if isMACBasedAuth(r.Packet) {
		logger = logger.WithField("mac", callingStationID)
		logger.Info("Processing MAC authentication")
		valid, err = s.authenticator.ValidateMAC(userName)
	} else if chapChallenge := rfc2865.CHAPChallenge_Get(r.Packet); chapChallenge != nil {
		// CHAP authentication
		logger.Info("Processing CHAP authentication")
		chapPassword := rfc2865.CHAPPassword_Get(r.Packet)
		if chapPassword == nil {
			authData.IsSuccess = false
			authData.FailureReason = "Missing CHAP password"
			s.exporter.SendAuthingData(authData)
			s.metrics.RecordAuthRequest(false, time.Since(start))
			sendAuthResponse(w, r, radius.CodeAccessReject, s.secret)
			return
		}
		valid, err = s.authenticator.ValidateCredentials(userName, "", auth.CHAP, chapChallenge, chapPassword)
	} else {
		// PAP authentication
		logger.Info("Processing PAP authentication")
		password := rfc2865.UserPassword_GetString(r.Packet)
		valid, err = s.authenticator.ValidateCredentials(userName, password, auth.PAP, nil, nil)
	}

	if err != nil {
		authData.IsSuccess = false
		authData.FailureReason = err.Error()
		s.exporter.SendAuthingData(authData)
		s.metrics.RecordAuthRequest(false, time.Since(start))
		sendAuthResponse(w, r, radius.CodeAccessReject, s.secret)
		return
	}

	if valid {
		authData.IsSuccess = true
		authData.FailureReason = ""
		s.exporter.SendAuthingData(authData)
		s.metrics.RecordAuthRequest(true, time.Since(start))
		sendAuthResponse(w, r, radius.CodeAccessAccept, s.secret)
	} else {
		authData.IsSuccess = false
		authData.FailureReason = "Invalid credentials"
		s.exporter.SendAuthingData(authData)
		s.metrics.RecordAuthRequest(false, time.Since(start))
		sendAuthResponse(w, r, radius.CodeAccessReject, s.secret)
	}
}

func (s *Server) handleAccountingRequest(w radius.ResponseWriter, r *radius.Request) {
	start := time.Now()

	packetIP := packetSourceIP(r)
	if packetIP == nil || packetIP.IsUnspecified() {
		packetIP = rfc2865.NASIPAddress_Get(r.Packet)
	}
	nasIPAddr := packetIP.String()
	userName := rfc2865.UserName_GetString(r.Packet)
	logger := s.log.WithFields(logrus.Fields{
		"username": userName,
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
	inputOctets := rfc2866.AcctInputOctets_Get(r.Packet)
	outputOctets := rfc2866.AcctOutputOctets_Get(r.Packet)

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

	acctData := &exporter.AccountingData{
		EventType:        eventType,
		Timestamp:        timestamp,
		EventTimestamp:   eventTimestamp,
		UserName:         userName,
		NasIdentifier:    nasIdentifier,
		NASIPAddr:        nasIPAddr,
		AcctSessionID:    sessionID,
		FramedIP:         framedIPAddr,
		CallingStationID: callingStationID,
		CalledStationID:  calledStationID,
		NasPort:          nasPort,
		NasPortType:      nasPortType,
		InputOctets:      uint32(inputOctets),
		OutputOctets:     uint32(outputOctets),
	}

	if err := s.exporter.SendAccountingData(acctData); err != nil {
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

func (s *Server) SendDisconnectRequest(nasIP string, userName string, macAddr string) error {
	start := time.Now()

	logger := s.log.WithFields(logrus.Fields{
		"username": userName,
		"nas":      nasIP,
		"mac":      macAddr,
	})

	nasIPAddr := net.ParseIP(nasIP)
	if nasIPAddr == nil || !s.nasValidator.IsAllowed(nasIPAddr) {
		logger.Warn("Unauthorized NAS IP address for CoA")
		s.metrics.RecordCoARequest(false, time.Since(start))
		return fmt.Errorf("unauthorized NAS IP")
	}

	// Create Disconnect-Request packet
	packet := radius.New(radius.CodeDisconnectRequest, []byte(s.secret))
	if userName != "" {
		rfc2865.UserName_SetString(packet, userName)
	}
	if macAddr != "" {
		rfc2865.CallingStationID_SetString(packet, macAddr)
	}
	rfc2865.NASIPAddress_Set(packet, net.ParseIP(nasIP))

	// Send to NAS
	ctx := context.Background()
	_, err := radius.Exchange(ctx, packet, nasIP+":3799")
	if err != nil {
		logger.WithError(err).Error("Failed to send Disconnect-Request")
		s.metrics.RecordCoARequest(false, time.Since(start))
		return err
	}

	// Also force disconnect in Redis
	var disconnectErr error
	if macAddr != "" {
		disconnectErr = s.authenticator.ForceDisconnectMacAddress(macAddr)
	} else if userName != "" {
		disconnectErr = s.authenticator.ForceDisconnectUser(userName)
	}

	if disconnectErr != nil {
		logger.WithError(disconnectErr).Error("Failed to force disconnect in Redis")
	}

	logger.Info("Successfully sent Disconnect-Request")
	s.metrics.RecordCoARequest(true, time.Since(start))
	return nil
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

	if err := s.exporter.Close(); err != nil {
		errs = append(errs, fmt.Errorf("error closing exporter: %w", err))
	} else {
		s.log.Info("Release exporter")
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
