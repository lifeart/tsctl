// Package web embeds the SPA served over the tailnet. Phase B (the frontend
// agent) replaces index.html with the real node list / picker / SSE UI.
package web

import "embed"

// FS holds the embedded static assets. Serve with http.FileServerFS(web.FS).
//
//go:embed index.html
var FS embed.FS
