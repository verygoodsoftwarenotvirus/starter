package encoding

import (
	"strings"
)

var (
	// ContentTypeJSON is to indicate we want JSON for some reason.
	ContentTypeJSON ContentType = buildContentType(contentTypeJSON)
	// ContentTypeXML is to indicate we want XML for some reason.
	ContentTypeXML ContentType = buildContentType(contentTypeXML)
	// ContentTypeEmoji is to indicate we want Emoji for some reason.
	ContentTypeEmoji ContentType = buildContentType(contentTypeEmoji)
)

type (
	// ContentType is the publicly accessible version of contentType.
	ContentType *contentType

	contentType *string
)

func (e *clientEncoder) ContentType() string {
	return contentTypeToString(e.contentType)
}

func buildContentType(s string) *contentType {
	ct := contentType(&s)

	return &ct
}

func contentTypeToString(c *contentType) string {
	switch c {
	case ContentTypeJSON:
		return contentTypeJSON
	case ContentTypeXML:
		return contentTypeXML
	case ContentTypeEmoji:
		return contentTypeEmoji
	default:
		return ""
	}
}

func contentTypeFromString(val string) ContentType {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case contentTypeJSON:
		return ContentTypeJSON
	case contentTypeXML:
		return ContentTypeXML
	case contentTypeEmoji:
		return ContentTypeEmoji
	default:
		return defaultContentType
	}
}
