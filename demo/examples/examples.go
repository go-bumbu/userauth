// Package examples defines the descriptor types the demo examples use to
// describe themselves. Each library aspect (auth methods, login flows,
// registration, profile, admin) contributes a Section; the demo router mounts
// every example through its Mount hook and renders the index page from the
// same data, so the selection page always reflects what is actually mounted.
package examples

import (
	"html/template"

	"github.com/gorilla/mux"
)

// Link is one entry point of an example, shown on the index page. Links
// without an Href (e.g. JSON endpoints) are rendered as plain code.
type Link struct {
	Href string
	Text string
	Desc string
}

// Example is one self-contained demo: the copy shown on the index page plus
// a Mount hook that registers its handlers on the demo router.
type Example struct {
	Title string
	Info  []template.HTML // info paragraphs; may contain inline markup like <code>
	Links []Link
	Mount func(r *mux.Router)
}

// Section groups the examples of one library aspect; it renders as one tab
// on the index page.
type Section struct {
	ID       string // tab id, also the value of the ?tab= URL parameter
	Title    string
	Info     []template.HTML
	Examples []Example
}
