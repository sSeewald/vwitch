// Package web holds the embedded UI assets: templates and static files.
package web

import "embed"

// Templates are the html/template sources.
//
//go:embed templates/*.html
var Templates embed.FS

// Static are CSS, JS and images served under /static/.
//
//go:embed static/*
var Static embed.FS
