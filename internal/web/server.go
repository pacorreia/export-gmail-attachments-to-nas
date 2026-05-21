package web

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/gmail"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/web/handlers"
)

//go:embed frontend/dist
var staticFiles embed.FS

// tokenAuth returns a middleware that enforces Bearer token authentication when
// the WEBAPP_TOKEN environment variable is set. If the variable is empty, auth
// is disabled and every request is allowed through.
func tokenAuth(next http.Handler) http.Handler {
	token := os.Getenv("WEBAPP_TOKEN")
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewRouter builds and returns the HTTP router.
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/health", handlers.Health)

	r.Get("/oauth/callback", gmail.CallbackHandler)

	r.Route("/api", func(r chi.Router) {
		r.Use(tokenAuth)

		r.Get("/accounts", handlers.ListAccounts)
		r.Delete("/accounts/{id}", handlers.DeleteAccount)
		r.Post("/accounts/oauth/start", handlers.StartOAuth)
		r.Post("/accounts/preview", handlers.PreviewGmailQuery)

		r.Get("/fileshares", handlers.ListFileShares)
		r.Post("/fileshares", handlers.CreateFileShare)
		r.Post("/fileshares/test", handlers.TestFileShareInline)
		r.Put("/fileshares/{id}", handlers.UpdateFileShare)
		r.Delete("/fileshares/{id}", handlers.DeleteFileShare)
		r.Post("/fileshares/{id}/test", handlers.TestFileShare)

		r.Get("/rules", handlers.ListRules)
		r.Post("/rules", handlers.CreateRule)
		r.Put("/rules/{id}", handlers.UpdateRule)
		r.Delete("/rules/{id}", handlers.DeleteRule)
		r.Get("/rules/{id}/assignments", handlers.GetRuleAssignments)
		r.Post("/rules/{id}/execute", handlers.ExecuteRule)
		r.Patch("/rules/{id}/toggle", handlers.ToggleRule)
		r.Delete("/rules/{id}/checkpoint", handlers.ResetRuleCheckpoint)

		r.Get("/plugins", handlers.ListPlugins)
		r.Post("/plugins", handlers.CreatePlugin)
		r.Put("/plugins/{id}", handlers.UpdatePlugin)
		r.Delete("/plugins/{id}", handlers.DeletePlugin)
		r.Post("/plugins/{id}/test", handlers.TestPlugin)

		r.Get("/logs", handlers.ListLogs)

		r.Get("/settings", handlers.GetSettings)
		r.Put("/settings", handlers.UpdateSettings)
	})

	staticFS, err := fs.Sub(staticFiles, "frontend/dist")
	if err != nil {
		log.Fatalf("web: failed to access embedded frontend: %v", err)
	}
	r.Handle("/*", http.FileServer(http.FS(staticFS)))

	return r
}
