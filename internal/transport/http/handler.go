package httptransport

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/auth"
	"github.com/lihongjie0209/identity-service/internal/buildinfo"
	"github.com/lihongjie0209/identity-service/internal/health"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
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
	Subject string `json:"subject"`
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
// @Success 200 {object} Response
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
	OK(c, gin.H{"account": account, "client_secret": secret})
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
// @Summary Return the authenticated subject
// @Tags authentication
// @Produce json
// @Security Bearer
// @Success 200 {object} Response{body=MeResponseBody}
// @Failure 401 {object} Response "Code 20001: unauthorized"
// @Router /api/v1/me [post]
func (h *Handler) Me(c *gin.Context) {
	subject, _ := c.Get("subject")
	OK(c, gin.H{"subject": subject})
}

// Version godoc
// @Summary Return build and runtime version information
// @Tags operations
// @Produce json
// @Success 200 {object} Response{body=buildinfo.Info}
// @Router /api/v1/version [post]
func (h *Handler) Version(c *gin.Context) { OK(c, buildinfo.Current()) }
