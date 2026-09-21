package controlplane

import "time"

// Public DTOs and explicit conversions are the single trust boundary through
// which persistence records reach the HTTP API and UI. Persistence structs
// (User, Registry, Membership, Invite) must never be marshaled or handed to a
// template directly; secrets such as User.PasswordHash, Registry.FeedKey
// (the at-rest AES-GCM envelope for the feed-owner signing key), and
// Invite.TokenHash have no public representation.

type PublicUser struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

func NewPublicUser(user User) PublicUser {
	return PublicUser{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}
}

type PublicRegistry struct {
	ID                  int64     `json:"id"`
	Slug                string    `json:"slug"`
	Host                string    `json:"host"`
	ENSName             string    `json:"ensName"`
	FeedOwnerAddress    string    `json:"feedOwnerAddress"`
	DefaultStampBatchID string    `json:"defaultStampBatchID"`
	AnonymousPull       bool      `json:"anonymousPull"`
	CreatedAt           time.Time `json:"createdAt"`
}

func NewPublicRegistry(registry Registry) PublicRegistry {
	return PublicRegistry{
		ID:                  registry.ID,
		Slug:                registry.Slug,
		Host:                registry.Host,
		ENSName:             registry.ENSName,
		FeedOwnerAddress:    registry.FeedOwnerAddress,
		DefaultStampBatchID: registry.DefaultStampBatchID,
		AnonymousPull:       registry.AnonymousPull,
		CreatedAt:           registry.CreatedAt,
	}
}

func newPublicRegistries(registries []Registry) []PublicRegistry {
	out := make([]PublicRegistry, 0, len(registries))
	for _, registry := range registries {
		out = append(out, NewPublicRegistry(registry))
	}
	return out
}

type PublicMembership struct {
	ID         int64     `json:"id"`
	RegistryID int64     `json:"registryID"`
	UserID     int64     `json:"userID"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	CanPull    bool      `json:"canPull"`
	CanPush    bool      `json:"canPush"`
	CreatedAt  time.Time `json:"createdAt"`
}

func NewPublicMembership(membership Membership) PublicMembership {
	return PublicMembership{
		ID:         membership.ID,
		RegistryID: membership.RegistryID,
		UserID:     membership.UserID,
		Email:      membership.Email,
		Role:       membership.Role,
		CanPull:    membership.CanPull,
		CanPush:    membership.CanPush,
		CreatedAt:  membership.CreatedAt,
	}
}

type PublicInvite struct {
	ID         int64     `json:"id"`
	RegistryID int64     `json:"registryID"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	CanPull    bool      `json:"canPull"`
	CanPush    bool      `json:"canPush"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expiresAt"`
	CreatedAt  time.Time `json:"createdAt"`
}

func NewPublicInvite(invite Invite) PublicInvite {
	return PublicInvite{
		ID:         invite.ID,
		RegistryID: invite.RegistryID,
		Email:      invite.Email,
		Role:       invite.Role,
		CanPull:    invite.CanPull,
		CanPush:    invite.CanPush,
		Status:     invite.Status,
		ExpiresAt:  invite.ExpiresAt,
		CreatedAt:  invite.CreatedAt,
	}
}

// PublicRegistryDashboard is the UI view-model for the registry settings page.
// It carries public DTOs only so persistence records never reach the template.
type PublicRegistryDashboard struct {
	Registry    PublicRegistry     `json:"registry"`
	Memberships []PublicMembership `json:"memberships"`
	Invites     []PublicInvite     `json:"invites"`
}

func NewPublicRegistryDashboard(dashboard RegistryDashboard) PublicRegistryDashboard {
	memberships := make([]PublicMembership, 0, len(dashboard.Memberships))
	for _, membership := range dashboard.Memberships {
		memberships = append(memberships, NewPublicMembership(membership))
	}
	invites := make([]PublicInvite, 0, len(dashboard.Invites))
	for _, invite := range dashboard.Invites {
		invites = append(invites, NewPublicInvite(invite))
	}
	return PublicRegistryDashboard{
		Registry:    NewPublicRegistry(dashboard.Registry),
		Memberships: memberships,
		Invites:     invites,
	}
}
