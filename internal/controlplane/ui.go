package controlplane

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "uncloud_session"

var layoutTemplate = template.Must(template.New("layout").Funcs(template.FuncMap{
	"prettyJSON": func(v any) string {
		data, _ := json.MarshalIndent(v, "", "  ")
		return string(data)
	},
	"displayRole": func(role string, canPush bool) string {
		switch role {
		case "owner":
			return "Owner"
		case "admin":
			return "Admin"
		default:
			if canPush {
				return "Write"
			}
			return "Read"
		}
	},
}).Parse(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      --bg: #f4efe7;
      --paper: rgba(255,255,255,0.82);
      --line: rgba(22, 33, 43, 0.12);
      --ink: #10202b;
      --muted: #5e6c75;
      --accent: #b4542f;
      --accent-2: #1f6a5c;
      --chip: #f4dfcf;
      --success: #d8f0e8;
      --shadow: 0 16px 40px rgba(16, 32, 43, 0.10);
      --radius: 22px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: Georgia, "Iowan Old Style", "Palatino Linotype", serif;
      background:
        radial-gradient(circle at top left, rgba(180, 84, 47, 0.18), transparent 32%),
        radial-gradient(circle at top right, rgba(31, 106, 92, 0.16), transparent 28%),
        linear-gradient(180deg, #f9f4ee 0%, var(--bg) 100%);
    }
    .shell {
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 24px 64px;
    }
    .hero {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      margin-bottom: 28px;
    }
    .brand {
      max-width: 680px;
    }
    .eyebrow {
      display: inline-flex;
      padding: 6px 12px;
      border-radius: 999px;
      background: var(--chip);
      color: var(--accent);
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 12px;
    }
    h1, h2, h3 { margin: 0; font-weight: 600; }
    h1 { font-size: clamp(2rem, 4vw, 4rem); line-height: 0.95; letter-spacing: -0.03em; }
    h2 { font-size: 1.4rem; margin-bottom: 12px; }
    h3 { font-size: 1rem; margin-bottom: 8px; }
    p { margin: 0; }
    .lede { color: var(--muted); font-size: 1.05rem; margin-top: 14px; max-width: 58ch; }
    .nav {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .nav a, .button, button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      text-decoration: none;
      background: var(--ink);
      color: #fff;
      padding: 12px 18px;
      font: inherit;
      cursor: pointer;
      box-shadow: var(--shadow);
    }
    .nav a.secondary, .button.secondary, button.secondary {
      background: rgba(255,255,255,0.5);
      color: var(--ink);
      border: 1px solid var(--line);
      box-shadow: none;
    }
    .flash {
      margin: 20px 0 24px;
      padding: 14px 16px;
      border-radius: 18px;
      background: var(--success);
      border: 1px solid rgba(31, 106, 92, 0.16);
    }
    .grid {
      display: grid;
      gap: 20px;
    }
    .grid.two {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .grid.three {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .card {
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 22px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }
    .registry-card {
      display: grid;
      gap: 18px;
      min-height: 220px;
    }
    .meta {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .chip {
      display: inline-flex;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(16,32,43,0.06);
      color: var(--muted);
      font-size: 0.9rem;
    }
    .muted { color: var(--muted); }
    .kicker { color: var(--accent); text-transform: uppercase; letter-spacing: 0.12em; font-size: 0.78rem; }
    form { display: grid; gap: 14px; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 0.95rem; }
    .checkbox-row {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      color: var(--ink);
    }
    .checkbox-row input {
      width: 18px;
      height: 18px;
      margin: 0;
      padding: 0;
      flex: 0 0 auto;
    }
    input, textarea, select {
      width: 100%;
      border-radius: 14px;
      border: 1px solid rgba(16, 32, 43, 0.14);
      padding: 14px 16px;
      font: inherit;
      background: rgba(255,255,255,0.9);
      color: var(--ink);
    }
    textarea { min-height: 220px; resize: vertical; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.9rem; }
    .stack { display: grid; gap: 16px; }
    .split {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
    }
    .table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.96rem;
    }
    .table td, .table th {
      padding: 10px 0;
      border-bottom: 1px solid rgba(16, 32, 43, 0.08);
      text-align: left;
      vertical-align: top;
    }
    .table th { color: var(--muted); font-weight: 500; }
    .code {
      font-family: ui-monospace, SFMono-Regular, monospace;
      background: rgba(16,32,43,0.06);
      border-radius: 10px;
      padding: 2px 8px;
      display: inline-block;
      max-width: 100%;
      white-space: nowrap;
      overflow-x: auto;
      overflow-y: hidden;
      vertical-align: middle;
    }
    .codeblock {
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, monospace;
      background: #13212a;
      color: #eef5f1;
      border-radius: 18px;
      padding: 16px;
      overflow: auto;
      font-size: 0.9rem;
      line-height: 1.45;
    }
    .link-box {
      display: grid;
      gap: 8px;
      padding: 14px;
      border-radius: 16px;
      border: 1px dashed rgba(180,84,47,0.35);
      background: rgba(244,223,207,0.5);
    }
    .empty {
      padding: 18px;
      border-radius: 16px;
      border: 1px dashed var(--line);
      color: var(--muted);
      background: rgba(255,255,255,0.35);
    }
    .permissions {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .policy-grid {
      display: grid;
      gap: 16px;
    }
    .policy-grid pre {
      margin: 0;
    }
    dialog {
      width: min(520px, calc(100vw - 32px));
      border: 0;
      border-radius: 22px;
      padding: 0;
      background: transparent;
    }
    dialog::backdrop {
      background: rgba(16, 32, 43, 0.45);
      backdrop-filter: blur(6px);
    }
    .modal-card {
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 22px;
      box-shadow: var(--shadow);
    }
    .error-box {
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(180, 84, 47, 0.12);
      border: 1px solid rgba(180, 84, 47, 0.22);
      color: #8a3315;
    }
    .table input[type="checkbox"] {
      width: 18px;
      height: 18px;
      margin: 0;
      display: block;
    }
    @media (max-width: 860px) {
      .hero { flex-direction: column; }
      .grid.two, .grid.three { grid-template-columns: 1fr; }
      .nav { justify-content: flex-start; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <div class="brand">
        <div class="eyebrow">Uncloud Registry</div>
        <h1>{{.Heading}}</h1>
        {{if .Lede}}<p class="lede">{{.Lede}}</p>{{end}}
      </div>
      {{if .Authenticated}}
      <div class="nav">
        <a class="secondary" href="/ui/registries">Dashboard</a>
        <a href="/ui/registries/new">Create Registry</a>
      </div>
      {{end}}
    </div>
    {{if .Message}}<div class="flash">{{.Message}}</div>{{end}}
    {{template "content" .}}
  </div>
  <script>
    document.addEventListener("click", async function (event) {
      const button = event.target.closest("[data-copy]");
      if (!button) return;
      const value = button.getAttribute("data-copy");
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        const original = button.textContent;
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = original; }, 1200);
      } catch (_) {}
    });
    document.addEventListener("click", function (event) {
      const openButton = event.target.closest("[data-dialog-open]");
      if (openButton) {
        const target = document.getElementById(openButton.getAttribute("data-dialog-open"));
        if (target && typeof target.showModal === "function") target.showModal();
      }
      const closeButton = event.target.closest("[data-dialog-close]");
      if (closeButton) {
        const dialog = closeButton.closest("dialog");
        if (dialog) dialog.close();
      }
    });
    document.addEventListener("DOMContentLoaded", function () {
      const autoOpen = document.querySelector("dialog[data-open-on-load='true']");
      if (autoOpen && typeof autoOpen.showModal === "function") autoOpen.showModal();
    });
  </script>
</body>
</html>`))

func (s *HTTPServer) handleUIRoot(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSessionUserID(r); ok {
		http.Redirect(w, r, "/ui/registries", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

func (s *HTTPServer) handleUILogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, pageData{
			Title:   "Login",
			Heading: "Ship images through Swarm-backed registries.",
			Lede:    "Sign in to manage registry settings, collaborators, policy publication, and Docker authentication.",
			Body: `
{{define "content"}}
<div class="grid two">
  <div class="card stack">
    <div>
      <div class="kicker">Login</div>
      <h2>Welcome back</h2>
      <p class="muted">Use your control-plane account to manage registries and invite collaborators.</p>
    </div>
    <form method="post" action="/ui/login">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <label>Email<input type="email" name="email" required></label>
      <label>Password<input type="password" name="password" required></label>
      <button type="submit">Login</button>
    </form>
  </div>
  <div class="card stack">
    <div class="kicker">Create account</div>
    <h2>New here?</h2>
    <p class="muted">Create an account first, then you can create registries or accept invite links from collaborators.</p>
    <a class="button secondary" href="/ui/register">Create an account</a>
  </div>
</div>
{{end}}`,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, token, err := s.Service.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
		if err != nil {
			s.renderPage(w, r, pageData{
				Title:   "Login",
				Heading: "Welcome back",
				Lede:    "Sign in to continue.",
				// Generic, identical failure message so the UI never reveals
				// whether the email exists.
				Message: "Invalid email or password.",
				Body: `
{{define "content"}}
<a class="button secondary" href="/ui/login">Try again</a>
{{end}}`,
			})
			return
		}
		s.setSessionCookie(w, token)
		http.Redirect(w, r, "/ui/registries", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) handleUIRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, pageData{
			Title:   "Register",
			Heading: "Create your control-plane account.",
			Lede:    "This account is used for registry administration, collaborator invites, and Docker token issuance.",
			Body: `
{{define "content"}}
<div class="grid two">
  <div class="card stack">
    <div class="kicker">Register</div>
    <h2>Get started</h2>
    <form method="post" action="/ui/register">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <label>Email<input type="email" name="email" required></label>
      <label>Password<input type="password" name="password" required></label>
      <button type="submit">Create account</button>
    </form>
  </div>
  <div class="card stack">
    <div class="kicker">Existing account</div>
    <h2>Already registered?</h2>
    <p class="muted">Log in instead and continue from your registry dashboard.</p>
    <a class="button secondary" href="/ui/login">Go to login</a>
  </div>
</div>
{{end}}`,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, token, err := s.Service.RegisterUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
		if err != nil {
			s.renderPage(w, r, pageData{
				Title:   "Register",
				Heading: "Create account",
				Lede:    "Set up a control-plane account.",
				Message: err.Error(),
				Body: `
{{define "content"}}
<a class="button secondary" href="/ui/register">Try again</a>
{{end}}`,
			})
			return
		}
		s.setSessionCookie(w, token)
		http.Redirect(w, r, "/ui/registries", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) handleUIRegistries(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registries, err := s.Service.ListRegistries(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	message := ""
	if r.URL.Query().Get("accepted") == "1" {
		message = "Invite accepted. The registry should now appear in your dashboard if the membership was published successfully."
	}
	s.renderPage(w, r, pageData{
		Title:         "Registries",
		Heading:       "Your registry dashboard.",
		Lede:          "Create and manage Swarm-backed registries, review access rules, publish policy updates, and invite collaborators.",
		Authenticated: true,
		Message:       message,
		Body: `
{{define "content"}}
<div class="split" style="margin-bottom:18px;">
  <div class="muted">Inspired by the Docker Hub repository flow, but focused on registry-level policy and collaborator management.</div>
  <a class="button" href="/ui/registries/new">Create new registry</a>
</div>
<div class="grid three">
  {{if not .Registries}}
  <div class="card empty">No registries yet. Create your first one to publish auth and stamp policy topics.</div>
  {{end}}
  {{range .Registries}}
  <a href="/ui/registries/{{.ID}}" style="text-decoration:none; color:inherit;">
    <div class="card registry-card">
      <div class="stack">
        <div class="kicker">Registry</div>
        <h2>{{.Slug}}</h2>
        <p class="muted">{{.Host}}</p>
      </div>
      <div class="meta">
        <span class="chip">{{if .AnonymousPull}}Anonymous pull on{{else}}Private pull{{end}}</span>
        <span class="chip">{{.ENSName}}</span>
      </div>
      <div class="stack">
        <div>
          <div class="kicker">Default stamp</div>
          <p class="code">{{.DefaultStampBatchID}}</p>
        </div>
        <div class="muted">Open settings, policy JSON, invite management, and acceptance links.</div>
      </div>
    </div>
  </a>
  {{end}}
</div>
{{end}}`,
		Data: map[string]any{"Registries": newPublicRegistries(registries)},
	})
}

func (s *HTTPServer) handleUICreateRegistry(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, pageData{
			Title:         "Create Registry",
			Heading:       "Create a registry.",
			Lede:          "Choose a registry slug, connect it to an ENS name, and set the initial default stamp and access mode.",
			Authenticated: true,
			Body: `
{{define "content"}}
<div class="grid two">
  <div class="card stack">
    <div class="kicker">Create</div>
    <h2>Registry details</h2>
    <form method="post" action="/ui/registries/new">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <label>Registry slug<input type="text" name="slug" placeholder="alice" required></label>
      <label>ENS name<input type="text" name="ens_name" placeholder="alice.registry.eth" required></label>
      <label>Default stamp batch ID<input type="text" name="default_stamp_batch_id" placeholder="batch-id" required></label>
      <label class="checkbox-row"><input type="checkbox" name="anonymous_pull" value="true"> <span>Allow anonymous pull</span></label>
      <button type="submit">Create registry</button>
    </form>
  </div>
  <div class="card stack">
    <div class="kicker">What happens</div>
    <h2>Bootstrap flow</h2>
    <p class="muted">The server generates a feed owner keypair, stores the signer privately, and publishes the initial auth and stamp policy topics.</p>
    <p class="muted">After creation, the detail page tells you which ENS address record to update so the registry host can resolve the correct owner.</p>
  </div>
</div>
{{end}}`,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		created, err := s.Service.CreateRegistry(
			r.Context(),
			userID,
			r.FormValue("slug"),
			r.FormValue("ens_name"),
			r.FormValue("anonymous_pull") == "true",
			r.FormValue("default_stamp_batch_id"),
		)
		if err != nil {
			s.renderPage(w, r, pageData{
				Title:         "Create Registry",
				Heading:       "Create a registry.",
				Lede:          "Choose registry details and publish bootstrap topics.",
				Authenticated: true,
				Message:       err.Error(),
				Body: `
{{define "content"}}
<a class="button secondary" href="/ui/registries/new">Back</a>
{{end}}`,
			})
			return
		}
		http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(created.Registry.ID, 10)+"?created=1", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) handleUIRegistryDetail(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registryID, ok := parseUIRegistryID(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dashboard, err := s.Service.GetRegistryDashboard(r.Context(), userID, registryID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	message := ""
	if r.URL.Query().Get("created") == "1" {
		message = "Registry created. Next step: update the ENS address record to the generated owner address below, then run the registry in ENS resolution mode."
	}
	if r.URL.Query().Get("updated") == "1" {
		message = "Registry settings updated and policy topics republished."
	}
	if r.URL.Query().Get("permissions_updated") == "1" {
		message = "Collaborator permissions updated and policies republished."
	}
	if r.URL.Query().Get("invite_stored") == "1" {
		message = "Invite created. The one-time share link could not be prepared; please create a new invite to share it."
	}
	if r.URL.Query().Get("invite_revoked") == "1" {
		message = "Invite revoked. The collaborator can no longer accept it."
	}
	if flashID := r.URL.Query().Get("invite_flash"); flashID != "" {
		// Consume the one-time flash atomically: only the authenticated creator of
		// THIS registry may retrieve it, once. Unknown, expired, wrong-user, and
		// wrong-registry requests reveal nothing. The raw token never appears in the
		// redirect URL, a cookie, a log, or an error.
		if token, ok := s.inviteFlash().consume(flashID, userID, registryID); ok {
			link := "/ui/invites/accept?token=" + url.QueryEscape(token)
			message = "Invite created. Share this link with the collaborator: " + absoluteURL(r, link)
		}
	}
	inviteModal := inviteModalState(r)
	dashboardDTO := NewPublicRegistryDashboard(dashboard)
	s.renderPage(w, r, pageData{
		Title:         dashboard.Registry.Slug,
		Heading:       dashboard.Registry.Slug + " settings",
		Lede:          "Manage registry access, default stamp policy, pending invites, and collaborator permissions from one place.",
		Authenticated: true,
		Message:       message,
		Body: `
{{define "content"}}
<div class="grid two">
  <div class="card stack">
    <div class="split">
      <div>
        <div class="kicker">Overview</div>
        <h2>{{.Dashboard.Registry.Host}}</h2>
      </div>
      <span class="chip">{{if .Dashboard.Registry.AnonymousPull}}Anonymous pull{{else}}Authenticated pull{{end}}</span>
    </div>
    <table class="table">
      <tr><th>ENS name</th><td><span class="code" title="{{.Dashboard.Registry.ENSName}}">{{.Dashboard.Registry.ENSName}}</span></td></tr>
      <tr><th>ENS address target</th><td><span class="code" title="{{.Dashboard.Registry.FeedOwnerAddress}}">{{.Dashboard.Registry.FeedOwnerAddress}}</span></td></tr>
      <tr><th>Default stamp</th><td><span class="code" title="{{.Dashboard.Registry.DefaultStampBatchID}}">{{.Dashboard.Registry.DefaultStampBatchID}}</span></td></tr>
    </table>
    <div class="link-box">
      <strong>ENS setup</strong>
      <div>Set the ENS address record for <span class="code" title="{{.Dashboard.Registry.ENSName}}">{{.Dashboard.Registry.ENSName}}</span> to <span class="code" title="{{.Dashboard.Registry.FeedOwnerAddress}}">{{.Dashboard.Registry.FeedOwnerAddress}}</span>.</div>
      <div class="muted">The registry server will then resolve the owner from ENS and derive the auth, stamp, and repo topics automatically.</div>
    </div>
  </div>
  <div class="card stack">
    <div class="kicker">Registry settings</div>
    <h2>Registry settings</h2>
    <form method="post" action="/ui/registries/{{.Dashboard.Registry.ID}}/settings">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <label>Default stamp batch ID<input type="text" name="default_stamp_batch_id" value="{{.Dashboard.Registry.DefaultStampBatchID}}" required></label>
      <label class="checkbox-row"><input type="checkbox" name="anonymous_pull" value="true" {{if .Dashboard.Registry.AnonymousPull}}checked{{end}}> <span>Allow anonymous pull</span></label>
      <button type="submit">Save and publish policy</button>
    </form>
    <div class="muted">Published policies are derived from registry settings and role-based access. Adding or accepting users does not rewrite policy topics.</div>
  </div>
</div>

<div class="card stack" style="margin-top:20px;">
  <div class="split">
    <div>
      <div class="kicker">Collaborators</div>
      <h2>Pending invites and accepted users</h2>
    </div>
    <button type="button" data-dialog-open="invite-dialog">Add user</button>
  </div>
  <div class="muted">Read/write access is stored per collaborator in the control plane. Published Swarm policies stay role-based: readers can pull, writers can pull and push. When anonymous pull is enabled, per-user pull selection is hidden.</div>
  <h3>Pending invites</h3>
  {{if not .Invites}}<div class="empty">No pending invites.</div>{{end}}
  {{if .Invites}}
  <table class="table">
    <tr>
      <th>Email</th>
      <th>Access</th>
      <th>Status</th>
      <th>Expires (UTC)</th>
      <th></th>
    </tr>
    {{range .Invites}}
    <tr>
      <td>{{.Email}}</td>
      <td>{{.Permissions}}</td>
      <td>{{.Status}}</td>
      <td>{{.ExpiresAt}}</td>
      <td>
        <form method="post" action="/ui/registries/{{$.Dashboard.Registry.ID}}/invites/{{.ID}}/revoke" style="display:inline;">
          <input type="hidden" name="_csrf" value="{{$.CSRF}}">
          <button class="secondary" type="submit">Revoke</button>
        </form>
      </td>
    </tr>
    {{end}}
  </table>
  {{end}}
  <h3>Accepted users</h3>
  <form method="post" action="/ui/registries/{{.Dashboard.Registry.ID}}/permissions">
    <input type="hidden" name="_csrf" value="{{$.CSRF}}">
    <table class="table">
      <tr>
        <th>Email</th>
        <th>Role</th>
        {{if not .Dashboard.Registry.AnonymousPull}}<th>Pull</th>{{end}}
        <th>Push</th>
      </tr>
      {{range .Dashboard.Memberships}}
      <tr>
        <td>{{if .Email}}<strong>{{.Email}}</strong>{{else}}<span class="muted">Unknown user</span>{{end}}</td>
        <td>{{displayRole .Role .CanPush}}</td>
        {{if not $.Dashboard.Registry.AnonymousPull}}
        <td>
          {{if or (eq .Role "owner") (eq .Role "admin")}}
          <input type="checkbox" checked disabled>
          {{else}}
          <input type="hidden" name="user_id" value="{{.UserID}}">
          <input type="checkbox" name="pull_{{.UserID}}" value="true" {{if .CanPull}}checked{{end}}>
          {{end}}
        </td>
        {{end}}
        <td>
          {{if or (eq .Role "owner") (eq .Role "admin")}}
          <input type="checkbox" checked disabled>
          {{else}}
          {{if $.Dashboard.Registry.AnonymousPull}}<input type="hidden" name="user_id" value="{{.UserID}}">{{end}}
          <input type="checkbox" name="push_{{.UserID}}" value="true" {{if .CanPush}}checked{{end}}>
          {{end}}
        </td>
      </tr>
      {{end}}
    </table>
    <button type="submit">Publish collaborator permissions</button>
  </form>
  <dialog id="invite-dialog" data-open-on-load="{{if .InviteModal.Open}}true{{else}}false{{end}}">
    <div class="modal-card stack">
      <div class="split">
        <div>
          <div class="kicker">Add user</div>
          <h2>Create invite</h2>
        </div>
        <button class="secondary" type="button" data-dialog-close>Close</button>
      </div>
      {{if .InviteModal.Error}}<div class="error-box">{{.InviteModal.Error}}</div>{{end}}
      <form method="post" action="/ui/registries/{{.Dashboard.Registry.ID}}/invites">
        <input type="hidden" name="_csrf" value="{{$.CSRF}}">
        <label>Email<input type="email" name="email" value="{{.InviteModal.Email}}" required></label>
        <div class="permissions">
          {{if not .Dashboard.Registry.AnonymousPull}}
          <label class="checkbox-row"><input type="checkbox" name="can_pull" value="true" {{if .InviteModal.CanPull}}checked{{end}}> <span>Read</span></label>
          {{end}}
          <label class="checkbox-row"><input type="checkbox" name="can_push" value="true" {{if .InviteModal.CanPush}}checked{{end}}> <span>Write</span></label>
        </div>
        <button type="submit">Create invite</button>
      </form>
    </div>
  </dialog>
{{end}}`,
		Data: map[string]any{
			"Dashboard":   dashboardDTO,
			"Invites":     inviteViewModels(dashboardDTO.Invites),
			"InviteModal": inviteModal,
		},
	})
}

func (s *HTTPServer) handleUIUpdateRegistrySettings(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registryID, ok := parseUIRegistryID(strings.TrimSuffix(r.URL.Path, "/settings"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := s.Service.UpdateRegistrySettings(
		r.Context(),
		userID,
		registryID,
		r.FormValue("anonymous_pull") == "true",
		r.FormValue("default_stamp_batch_id"),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10)+"?updated=1", http.StatusSeeOther)
}

func (s *HTTPServer) handleUICreateInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registryID, ok := parseUIRegistryID(strings.TrimSuffix(r.URL.Path, "/invites"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	canPull := r.FormValue("can_pull") == "true"
	canPush := r.FormValue("can_push") == "true"
	_, token, err := s.Service.CreateInvite(r.Context(), registryID, userID, r.FormValue("email"), canPull, canPush)
	if err != nil {
		query := url.Values{}
		query.Set("invite_modal", "1")
		query.Set("invite_error", err.Error())
		query.Set("invite_email", r.FormValue("email"))
		if canPull {
			query.Set("invite_can_pull", "1")
		}
		if canPush {
			query.Set("invite_can_push", "1")
		}
		http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10)+"?"+query.Encode(), http.StatusSeeOther)
		return
	}
	// Store the one-time raw token in a transient, principal/registry-bound flash and
	// carry only a random opaque flash ID in the 303 redirect URL. If the store fails
	// safely (e.g. at capacity) we still 303-redirect but render no token; the invite
	// itself is already persisted and remains visible in the pending list.
	flashID, flashErr := s.inviteFlash().store(token, userID, registryID)
	if flashErr != nil {
		http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10)+"?invite_stored=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10)+"?invite_flash="+url.QueryEscape(flashID), http.StatusSeeOther)
}

// handleUIRevokeInvite is the UI revocation boundary: owner/admin only (the
// service enforces it), pending invites only, atomic and idempotent for the
// same authorized request. Every unauthorized/terminal/unknown case redirects
// through a generic result — a revoked invite disappears from the pending
// list; nothing about token or digest material is ever rendered.
func (s *HTTPServer) handleUIRevokeInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registryID, inviteID, ok := parseInviteRevokePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := s.Service.RevokeInvite(r.Context(), userID, registryID, inviteID); err != nil {
		if errors.Is(err, errInviteNotFound) || errors.Is(err, errInviteCannotRevoke) {
			http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10), http.StatusSeeOther)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10)+"?invite_revoked=1", http.StatusSeeOther)
}

func (s *HTTPServer) handleUIUpdateCollaboratorPermissions(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSessionUser(w, r)
	if !ok {
		return
	}
	registryID, ok := parseUIRegistryID(strings.TrimSuffix(r.URL.Path, "/permissions"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userIDs := r.Form["user_id"]
	updates := make([]Membership, 0, len(userIDs))
	for _, rawID := range userIDs {
		memberUserID, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil {
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}
		canPull := r.FormValue("pull_"+rawID) == "true"
		canPush := r.FormValue("push_"+rawID) == "true"
		if canPush {
			canPull = true
		}
		updates = append(updates, Membership{
			UserID:  memberUserID,
			CanPull: canPull,
			CanPush: canPush,
		})
	}
	if _, err := s.Service.UpdateCollaboratorPermissions(r.Context(), userID, registryID, updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/ui/registries/"+strconv.FormatInt(registryID, 10)+"?permissions_updated=1", http.StatusSeeOther)
}

func (s *HTTPServer) handleUIAcceptInvite(w http.ResponseWriter, r *http.Request) {
	// The raw query value is passed EXACTLY as received — no TrimSpace or any
	// other mutation before the strict canonical ParseInviteToken, so
	// whitespace-padded tokens are rejected, never silently accepted.
	token := r.URL.Query().Get("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	invite, registry, err := s.Service.GetInvite(r.Context(), token)
	if err != nil {
		// Revoked, expired, accepted, unknown, and malformed tokens all render
		// the same generic page; nothing distinguishes invite states.
		if errors.Is(err, errInviteNotFound) {
			http.Error(w, "This invite link is not valid or has expired.", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		_, signedIn := s.requireSessionUserID(r)
		body := `
{{define "content"}}
<div class="grid two">
  <div class="card stack">
    <div class="kicker">Invite</div>
    <h2>{{.Invite.Email}}</h2>
    <p class="muted">You were invited to collaborate on <span class="code">{{.Registry.Host}}</span> with <strong>{{.InvitePermissions}}</strong> access.</p>
    <p class="muted">The registry currently uses ENS name <span class="code">{{.Registry.ENSName}}</span>.</p>
  </div>
  <div class="card stack">
    <div class="kicker">Accept invite</div>
    <h2>{{if .SignedIn}}Confirm access{{else}}Create account and accept{{end}}</h2>
    {{if .SignedIn}}
    <form method="post" action="/ui/invites/accept?token={{.Token}}">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <button type="submit">Accept invite</button>
    </form>
    {{else}}
    <form method="post" action="/ui/invites/accept?token={{.Token}}">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <label>Email<input type="email" name="email" value="{{.Invite.Email}}" required></label>
      <label>Password<input type="password" name="password" required></label>
      <button type="submit">Create account and accept invite</button>
    </form>
    {{end}}
  </div>
</div>
{{end}}`
		s.renderPage(w, r, pageData{
			Title:         "Accept Invite",
			Heading:       "Accept collaborator invite.",
			Lede:          "This flow creates a control-plane account if needed, then grants access to the registry.",
			Authenticated: signedIn,
			Body:          body,
			Data: map[string]any{
				"Invite":            NewPublicInvite(invite),
				"InvitePermissions": permissionLabel(invite.CanPull, invite.CanPush),
				"Registry":          NewPublicRegistry(registry),
				"Token":             token,
				"SignedIn":          signedIn,
			},
		})
	case http.MethodPost:
		if userID, ok := s.requireSessionUserID(r); ok {
			if _, err := s.Service.AcceptInvite(r.Context(), token, userID); err != nil {
				if errors.Is(err, errInviteNotFound) {
					http.Error(w, "This invite link is not valid or has expired.", http.StatusNotFound)
					return
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, "/ui/registries?accepted=1", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _, sessionToken, err := s.Service.RegisterAndAcceptInvite(r.Context(), token, r.FormValue("email"), r.FormValue("password"))
		if err != nil {
			if errors.Is(err, errInviteNotFound) {
				http.Error(w, "This invite link is not valid or has expired.", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.setSessionCookie(w, sessionToken)
		http.Redirect(w, r, "/ui/registries?accepted=1", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) setSessionCookie(w http.ResponseWriter, token string) {
	ttl := s.security.sessionTTL
	if s.security == nil || ttl <= 0 {
		ttl = 24 * time.Hour
	}
	var maxAge int
	if lim := ttl.Seconds(); lim > float64(int(^uint(0)>>1)) {
		maxAge = int(^uint(0) >> 1)
	} else {
		maxAge = int(lim)
	}
	http.SetCookie(w, s.sessionCookie(token, maxAge))
}

// clearSessionCookie expires the session cookie with attributes identical to
// the one that was set, so browsers remove it.
func (s *HTTPServer) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, s.sessionCookie("", -1))
}

// sessionCookie builds the control plane's single, fixed session cookie:
// HttpOnly, SameSite=Lax, Path=/, bounded MaxAge, Secure when the deployment
// warrants it (validated mode plus external URL), and never a Domain attribute,
// so the cookie can never be scoped onto a host the server does not serve.
func (s *HTTPServer) sessionCookie(token string, maxAge int) *http.Cookie {
	secure := false
	if s.security != nil {
		secure = s.security.secureCookie
	}
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// handleLogout clears the session cookie and returns the user to login. It is
// a cookie-authenticated POST, so it is protected by the session-bound CSRF
// control like any other mutation.
func (s *HTTPServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

type pageData struct {
	Title         string
	Heading       string
	Lede          string
	Message       string
	Authenticated bool
	CSRF          string
	Body          string
	Data          map[string]any
}

func (s *HTTPServer) renderPage(w http.ResponseWriter, r *http.Request, page pageData) {
	if s.security != nil {
		page.CSRF = s.security.sessionCSRF(r)
	}
	tmpl, err := layoutTemplate.Clone()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl, err = tmpl.Parse(page.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	payload := map[string]any{
		"Title":         page.Title,
		"Heading":       page.Heading,
		"Lede":          page.Lede,
		"Message":       page.Message,
		"Authenticated": page.Authenticated,
		"CSRF":          page.CSRF,
	}
	for key, value := range page.Data {
		payload[key] = value
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, payload)
}

type inviteViewModel struct {
	ID          string
	Email       string
	Permissions string
	Status      string
	ExpiresAt   string
}

type inviteModalView struct {
	Open    bool
	Error   string
	Email   string
	CanPull bool
	CanPush bool
}

// inviteViewModels builds owner-facing pending-invite rows from public invite
// DTOs only. It intentionally never reads the persistence Invite.TokenDigest:
// the one-time raw invite token is returned once in the invite-creation
// response and the digest must never be reconstructed for the detail page.
// Each pending row exposes only recipient, permissions, state, and expiry —
// the revoke button uses the invite ID, never any credential material.
func inviteViewModels(invites []PublicInvite) []inviteViewModel {
	models := make([]inviteViewModel, 0, len(invites))
	for _, invite := range invites {
		if invite.Status != "pending" {
			continue
		}
		models = append(models, inviteViewModel{
			ID:          strconv.FormatInt(invite.ID, 10),
			Email:       invite.Email,
			Permissions: permissionLabel(invite.CanPull, invite.CanPush),
			Status:      invite.Status,
			ExpiresAt:   invite.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	return models
}

func permissionLabel(canPull bool, canPush bool) string {
	switch {
	case canPush:
		return "Read + Write"
	case canPull:
		return "Read"
	default:
		return "no access"
	}
}

func inviteModalState(r *http.Request) inviteModalView {
	query := r.URL.Query()
	return inviteModalView{
		Open:    query.Get("invite_modal") == "1",
		Error:   query.Get("invite_error"),
		Email:   query.Get("invite_email"),
		CanPull: query.Get("invite_can_pull") == "1",
		CanPush: query.Get("invite_can_push") == "1",
	}
}

func absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

func parseUIRegistryID(path string) (int64, bool) {
	trimmed := strings.TrimPrefix(path, "/ui/registries/")
	if trimmed == "" {
		return 0, false
	}
	parts := strings.SplitN(trimmed, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
