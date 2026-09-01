package httptransport

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/auth"
	"github.com/lihongjie0209/identity-service/internal/buildinfo"
	"github.com/lihongjie0209/identity-service/internal/health"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

type Handler struct {
	auth       *auth.Service
	logger     *slog.Logger
	health     *health.Service
	identities *identitydomain.Service
}

func NewHandler(authService *auth.Service, healthService *health.Service, identities *identitydomain.Service, logger *slog.Logger) *Handler {
	return &Handler{auth: authService, health: healthService, identities: identities, logger: logger}
}

type LoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}
type LogoutRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	Reason    string `json:"reason"`
}
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}
type ChangePasswordResponseBody struct {
	Changed         bool   `json:"changed"`
	RevokedSessions uint64 `json:"revoked_sessions"`
}
type ListSessionsRequest struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type RevokeSessionRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	Reason    string `json:"reason" binding:"required"`
	Version   int64  `json:"version" binding:"required"`
}
type SessionResponseBody struct {
	SessionID    string     `json:"session_id"`
	UserID       string     `json:"user_id"`
	TenantID     string     `json:"tenant_id"`
	MembershipID string     `json:"membership_id"`
	Status       string     `json:"status"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
	LastUsedAt   time.Time  `json:"last_used_at"`
	Version      int64      `json:"version"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CreatedBy    string     `json:"created_by"`
	UpdatedBy    string     `json:"updated_by"`
}
type SessionPageResponseBody struct {
	Items    []SessionResponseBody `json:"items"`
	Total    int64                 `json:"total"`
	Page     int                   `json:"page"`
	PageSize int                   `json:"page_size"`
}
type RegisterIdentityRequest struct {
	Username    string `json:"username" binding:"required"`
	DisplayName string `json:"display_name" binding:"required"`
	Email       string `json:"email" binding:"required"`
	Phone       string `json:"phone"`
	Password    string `json:"password" binding:"required"`
}
type CreateServiceAccountRequest struct {
	Name      string   `json:"name" binding:"required"`
	Audiences []string `json:"audiences" binding:"required"`
}
type ListServiceAccountsRequest struct {
	Keyword  string `json:"keyword"`
	Status   string `json:"status"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type ServiceAccountResponseBody struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Audiences []string  `json:"audiences"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedBy string    `json:"updated_by"`
}
type ServiceAccountPageResponseBody struct {
	Items    []ServiceAccountResponseBody `json:"items"`
	Total    int64                        `json:"total"`
	Page     int                          `json:"page"`
	PageSize int                          `json:"page_size"`
}
type CreateServiceAccountResponseBody struct {
	Account      ServiceAccountResponseBody `json:"account"`
	ClientSecret string                     `json:"client_secret"`
}
type UpdateServiceAccountStatusRequest struct {
	ID      string `json:"id" binding:"required"`
	Status  string `json:"status" binding:"required"`
	Version int64  `json:"version" binding:"required"`
}
type ServiceAccountTokenRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
}
type IdentityResponseBody struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Status      string `json:"status"`
	Version     int64  `json:"version"`
}
type UpdateIdentityStatusRequest struct {
	ID      string `json:"id" binding:"required"`
	Status  string `json:"status" binding:"required"`
	Reason  string `json:"reason"`
	Version int64  `json:"version" binding:"required"`
}
type ListIdentitiesRequest struct {
	Keyword  string `json:"keyword"`
	Status   string `json:"status"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type LoginResponseBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}
type MeResponseBody struct {
	Subject      string   `json:"subject"`
	SubjectType  string   `json:"subject_type"`
	SessionID    string   `json:"session_id,omitempty"`
	TenantID     string   `json:"tenant_id,omitempty"`
	MembershipID string   `json:"membership_id,omitempty"`
	Username     string   `json:"username,omitempty"`
	DisplayName  string   `json:"display_name,omitempty"`
	Email        string   `json:"email,omitempty"`
	Phone        string   `json:"phone,omitempty"`
	Status       string   `json:"status,omitempty"`
	Roles        []string `json:"roles"`
	Buttons      []string `json:"buttons"`
}

// Login godoc
// @Summary Issue a JWT access token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Username/email and password"
// @Success 200 {object} Response{body=identity.Tokens}
// @Failure 400 {object} Response "Code 10001: invalid request"
// @Failure 401 {object} Response "Code 20001: invalid credentials"
// @Failure 429 {object} Response "Code 10029: rate limited"
// @Router /api/v1/auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	tokens, err := h.identities.Login(c.Request.Context(), req.Login, req.Password)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, tokens)
}

// Refresh godoc
// @Summary Rotate a refresh token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh token"
// @Success 200 {object} Response{body=identity.Tokens}
// @Router /api/v1/auth/refresh [post]
func (h *Handler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	tokens, err := h.identities.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, tokens)
}

// Logout godoc
// @Summary Revoke the current session
// @Tags authentication
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "Session"
// @Success 200 {object} Response
// @Router /api/v1/auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	if err := h.identities.Logout(c.Request.Context(), req.SessionID, req.Reason); err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, gin.H{"revoked": true})
}

// ChangePassword godoc
// @Summary Change the current user's password and revoke other active sessions
// @Tags authentication
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Current and new password"
// @Success 200 {object} Response{body=ChangePasswordResponseBody}
// @Failure 400 {object} Response "Code 10001: invalid password"
// @Failure 401 {object} Response "Code 20001: current password is invalid"
// @Router /api/v1/auth/change-password [post]
func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	revokedSessions, err := h.identities.ChangePassword(
		c.Request.Context(),
		req.CurrentPassword,
		req.NewPassword,
	)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, ChangePasswordResponseBody{Changed: true, RevokedSessions: revokedSessions})
}

// ListSessions godoc
// @Summary List user sessions for security administration
// @Tags sessions
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body ListSessionsRequest true "Filters and pagination"
// @Success 200 {object} Response{body=SessionPageResponseBody}
// @Router /api/v1/sessions/list [post]
func (h *Handler) ListSessions(c *gin.Context) {
	var req ListSessionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	page, err := h.identities.ListSessions(
		c.Request.Context(),
		req.UserID,
		req.TenantID,
		req.Status,
		req.Page,
		req.PageSize,
	)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	now := time.Now().UTC()
	items := make([]SessionResponseBody, 0, len(page.Items))
	for _, session := range page.Items {
		items = append(items, sessionResponse(session, now))
	}
	OK(c, SessionPageResponseBody{
		Items:    items,
		Total:    page.Total,
		Page:     page.Page,
		PageSize: page.PageSize,
	})
}

// RevokeSession godoc
// @Summary Administratively revoke a session with optimistic locking
// @Tags sessions
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body RevokeSessionRequest true "Session, reason, and expected version"
// @Success 200 {object} Response{body=SessionResponseBody}
// @Failure 409 {object} Response "Code 30009: stale resource version"
// @Router /api/v1/sessions/revoke [post]
func (h *Handler) RevokeSession(c *gin.Context) {
	var req RevokeSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	session, err := h.identities.RevokeSessionByID(
		c.Request.Context(),
		req.SessionID,
		req.Reason,
		req.Version,
	)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, sessionResponse(session, time.Now().UTC()))
}

// RegisterIdentity godoc
// @Summary Register a user identity
// @Tags identities
// @Security Bearer
// @Security PSK
// @Accept json
// @Produce json
// @Param request body RegisterIdentityRequest true "Identity"
// @Success 200 {object} Response{body=IdentityResponseBody}
// @Router /api/v1/identities/register [post]
func (h *Handler) RegisterIdentity(c *gin.Context) {
	var req RegisterIdentityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	created, err := h.identities.Register(c.Request.Context(), req.Username, req.DisplayName, req.Email, req.Phone, req.Password)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, created)
}

// ListIdentities godoc
// @Summary List user identities
// @Tags identities
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body ListIdentitiesRequest true "Filters and pagination"
// @Success 200 {object} Response
// @Router /api/v1/identities/list [post]
func (h *Handler) ListIdentities(c *gin.Context) {
	var req ListIdentitiesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	page, err := h.identities.ListUsers(c.Request.Context(), req.Keyword, req.Status, req.Page, req.PageSize)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, page)
}

// UpdateIdentityStatus godoc
// @Summary Update user status with optimistic locking
// @Tags identities
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body UpdateIdentityStatusRequest true "Status and version"
// @Success 200 {object} Response{body=IdentityResponseBody}
// @Router /api/v1/identities/update-status [post]
func (h *Handler) UpdateIdentityStatus(c *gin.Context) {
	var req UpdateIdentityStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	updated, err := h.identities.UpdateUserStatus(c.Request.Context(), req.ID, req.Status, req.Reason, req.Version)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, updated)
}

// JWKS godoc
// @Summary Return active and grace-period verification keys
// @Tags authentication
// @Produce json
// @Success 200 {object} identity.JWKS
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(c *gin.Context) { c.JSON(200, h.identities.JWKS()) }

// CreateServiceAccount godoc
// @Summary Create a service account and return its secret once
// @Tags service-accounts
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body CreateServiceAccountRequest true "Service account"
// @Success 200 {object} Response{body=CreateServiceAccountResponseBody}
// @Router /api/v1/service-accounts/create [post]
func (h *Handler) CreateServiceAccount(c *gin.Context) {
	var req CreateServiceAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	account, secret, err := h.identities.CreateServiceAccount(c.Request.Context(), req.Name, req.Audiences)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, CreateServiceAccountResponseBody{
		Account:      serviceAccountResponse(account),
		ClientSecret: secret,
	})
}

// ListServiceAccounts godoc
// @Summary List service accounts
// @Tags service-accounts
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body ListServiceAccountsRequest true "Filters and pagination"
// @Success 200 {object} Response{body=ServiceAccountPageResponseBody}
// @Router /api/v1/service-accounts/list [post]
func (h *Handler) ListServiceAccounts(c *gin.Context) {
	var req ListServiceAccountsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	page, err := h.identities.ListServiceAccounts(
		c.Request.Context(),
		req.Keyword,
		req.Status,
		req.Page,
		req.PageSize,
	)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	items := make([]ServiceAccountResponseBody, 0, len(page.Items))
	for _, account := range page.Items {
		items = append(items, serviceAccountResponse(account))
	}
	OK(c, ServiceAccountPageResponseBody{
		Items:    items,
		Total:    page.Total,
		Page:     page.Page,
		PageSize: page.PageSize,
	})
}

// UpdateServiceAccountStatus godoc
// @Summary Enable or disable a service account with optimistic locking
// @Tags service-accounts
// @Security Bearer
// @Accept json
// @Produce json
// @Param request body UpdateServiceAccountStatusRequest true "Status and version"
// @Success 200 {object} Response
// @Router /api/v1/service-accounts/update-status [post]
func (h *Handler) UpdateServiceAccountStatus(c *gin.Context) {
	var req UpdateServiceAccountStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	if err := h.identities.UpdateServiceAccountStatus(c.Request.Context(), req.ID, req.Status, req.Version); err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, gin.H{"updated": true})
}

// ServiceAccountToken godoc
// @Summary Issue a service-account access token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body ServiceAccountTokenRequest true "Client credentials"
// @Success 200 {object} Response
// @Router /api/v1/auth/service-token [post]
func (h *Handler) ServiceAccountToken(c *gin.Context) {
	var req ServiceAccountTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, h.logger, apperror.Invalid("invalid json request", err))
		return
	}
	token, expiresAt, err := h.identities.ServiceAccountToken(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		Fail(c, h.logger, err)
		return
	}
	OK(c, gin.H{"access_token": token, "token_type": "Bearer", "expires_at": expiresAt})
}

// Live godoc
// @Summary Check process liveness
// @Tags operations
// @Produce json
// @Success 200 {object} Response{body=health.Status}
// @Router /live [post]
func (h *Handler) Live(c *gin.Context) { OK(c, h.health.Live()) }

// Ready godoc
// @Summary Check database and Redis readiness
// @Tags operations
// @Produce json
// @Success 200 {object} Response{body=health.Status}
// @Failure 503 {object} Response{body=health.Status} "Code 50003: dependency unavailable"
// @Router /ready [post]
func (h *Handler) Ready(c *gin.Context) {
	status, ready := h.health.Ready(c.Request.Context())
	if !ready {
		c.JSON(503, Response{Code: apperror.CodeDependencyUnavailable, Message: "service is not ready", Body: status, RequestID: requestID(c)})
		return
	}
	OK(c, status)
}

// Me godoc
// @Summary Return the authenticated subject and current user profile
// @Tags authentication
// @Produce json
// @Security Bearer
// @Success 200 {object} Response{body=MeResponseBody}
// @Failure 401 {object} Response "Code 20001: unauthorized"
// @Router /api/v1/me [post]
func (h *Handler) Me(c *gin.Context) {
	actor, err := principal.Require(c.Request.Context())
	if err != nil {
		Fail(c, h.logger, apperror.Unauthorized("authenticated actor is required"))
		return
	}
	response := MeResponseBody{
		Subject:      actor.ID,
		SubjectType:  string(actor.Type),
		SessionID:    actor.SessionID,
		TenantID:     actor.TenantID,
		MembershipID: actor.MembershipID,
		Roles:        []string{},
		Buttons:      []string{},
	}
	if actor.Type == principal.TypeUser {
		user, err := h.identities.GetUser(c.Request.Context(), actor.ID)
		if err != nil {
			Fail(c, h.logger, err)
			return
		}
		response.Username = user.Username
		response.DisplayName = user.DisplayName
		response.Email = user.Email
		response.Phone = user.Phone
		response.Status = user.Status
	}
	OK(c, response)
}

// Version godoc
// @Summary Return build and runtime version information
// @Tags operations
// @Produce json
// @Success 200 {object} Response{body=buildinfo.Info}
// @Router /api/v1/version [post]
func (h *Handler) Version(c *gin.Context) { OK(c, buildinfo.Current()) }

func serviceAccountResponse(account identitydomain.ServiceAccount) ServiceAccountResponseBody {
	return ServiceAccountResponseBody{
		ID:        account.ID,
		ClientID:  account.ClientID,
		Name:      account.Name,
		Status:    account.Status,
		Audiences: account.Audiences,
		Version:   account.Version,
		CreatedAt: account.CreatedAt,
		UpdatedAt: account.UpdatedAt,
		CreatedBy: account.CreatedBy,
		UpdatedBy: account.UpdatedBy,
	}
}

func sessionResponse(session identitydomain.Session, now time.Time) SessionResponseBody {
	status := "active"
	if session.RevokedAt != nil {
		status = "revoked"
	} else if !session.ExpiresAt.After(now) {
		status = "expired"
	}
	return SessionResponseBody{
		SessionID:    session.ID,
		UserID:       session.UserID,
		TenantID:     session.TenantID,
		MembershipID: session.MembershipID,
		Status:       status,
		ExpiresAt:    session.ExpiresAt,
		RevokedAt:    session.RevokedAt,
		RevokeReason: session.RevokeReason,
		LastUsedAt:   session.LastUsedAt,
		Version:      session.Version,
		CreatedAt:    session.CreatedAt,
		UpdatedAt:    session.UpdatedAt,
		CreatedBy:    session.CreatedBy,
		UpdatedBy:    session.UpdatedBy,
	}
}
