package controllers

import (
	"github.com/DipsDev/mason/templates/pages"
	"net/http"
)

func ShowPanelFrame(w http.ResponseWriter, r *http.Request) {
	pages.Panel("Panel", pages.EmptyPanel()).Render(r.Context(), w)

}

func ShowPanelOverview(w http.ResponseWriter, r *http.Request) {
	pages.Panel("Overview", pages.Overview()).Render(r.Context(), w)

}

func ShowPanelSettings(w http.ResponseWriter, r *http.Request) {
	pages.Panel("Panel Settings", pages.Settings()).Render(r.Context(), w)
}

func ShowPanelPages(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "" {
		pages.Panel("Pages", pages.Pages()).Render(r.Context(), w)
		return
	}
	pages.Pages().Render(r.Context(), w)
}
