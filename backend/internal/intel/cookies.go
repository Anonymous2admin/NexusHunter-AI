package intel

import (
	"net/http"
	"strings"
)

// ParsedCookie summarizes a cookie's name, security flags, and attributes.
type ParsedCookie struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
	Raw      string `json:"raw"`
}

// ParseCookies extracts parsed cookies from Set-Cookie header lines.
func ParseCookies(rawCookies []string) []ParsedCookie {
	var result []ParsedCookie
	for _, raw := range rawCookies {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		// Use standard net/http cookie parser
		header := http.Header{}
		header.Add("Set-Cookie", raw)
		req := http.Response{Header: header}
		cookies := req.Cookies()
		if len(cookies) > 0 {
			c := cookies[0]
			sameSite := "None"
			switch c.SameSite {
			case http.SameSiteLaxMode:
				sameSite = "Lax"
			case http.SameSiteStrictMode:
				sameSite = "Strict"
			case http.SameSiteNoneMode:
				sameSite = "None"
			}
			result = append(result, ParsedCookie{
				Name:     c.Name,
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
				SameSite: sameSite,
				Raw:      raw,
			})
		} else {
			// Fallback string parsing
			parts := strings.Split(raw, ";")
			nameVal := strings.SplitN(parts[0], "=", 2)
			name := strings.TrimSpace(nameVal[0])
			lower := strings.ToLower(raw)
			result = append(result, ParsedCookie{
				Name:     name,
				Secure:   strings.Contains(lower, "secure"),
				HttpOnly: strings.Contains(lower, "httponly"),
				SameSite: "Unknown",
				Raw:      raw,
			})
		}
	}
	return result
}
