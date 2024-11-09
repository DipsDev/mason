package controllers

import (
	"github.com/DipsDev/mason/templates/pages"
	"net/http"
)

func ShowPanelFrame(w http.ResponseWriter, r *http.Request) {
	pages.EmptyPanel().Render(r.Context(), w)

}

func ShowPanelOverview(w http.ResponseWriter, r *http.Request) {
	pages.Overview().Render(r.Context(), w)

}

func ShowPanelSettings(w http.ResponseWriter, r *http.Request) {
	pages.Settings().Render(r.Context(), w)
}

func ShowPanelPages(w http.ResponseWriter, r *http.Request) {
	pages.Pages().Render(r.Context(), w)
}
