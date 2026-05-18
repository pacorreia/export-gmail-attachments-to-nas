package web

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/gmail"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/web/handlers"
)

//go:embed static
var staticFiles embed.FS

// NewRouter builds and returns the HTTP router.
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/oauth/callback", gmail.CallbackHandler)

	r.Route("/api", func(r chi.Router) {
		r.Get("/accounts", handlers.ListAccounts)
		r.Delete("/accounts/{id}", handlers.DeleteAccount)
		r.Post("/accounts/oauth/start", handlers.StartOAuth)
		r.Post("/accounts/preview", handlers.PreviewGmailQuery)

		r.Get("/fileshares", handlers.ListFileShares)
		r.Post("/fileshares", handlers.CreateFileShare)
		r.Delete("/fileshares/{id}", handlers.DeleteFileShare)
		r.Post("/fileshares/{id}/test", handlers.TestFileShare)

		r.Get("/rules", handlers.ListRules)
		r.Post("/rules", handlers.CreateRule)
		r.Put("/rules/{id}", handlers.UpdateRule)
		r.Delete("/rules/{id}", handlers.DeleteRule)
		r.Get("/rules/{id}/assignments", handlers.GetRuleAssignments)

		r.Get("/plugins", handlers.ListPlugins)
		r.Post("/plugins", handlers.CreatePlugin)
		r.Put("/plugins/{id}", handlers.UpdatePlugin)
		r.Delete("/plugins/{id}", handlers.DeletePlugin)
		r.Post("/plugins/{id}/test", handlers.TestPlugin)

		r.Get("/logs", handlers.ListLogs)

		r.Get("/settings", handlers.GetSettings)
		r.Put("/settings", handlers.UpdateSettings)
	})

	staticFS, _ := fs.Sub(staticFiles, "static")
	r.Handle("/*", http.FileServer(http.FS(staticFS)))

	return r
}
