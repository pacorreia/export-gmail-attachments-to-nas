package gmail

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"mime"
	"net/mail"
	"strings"
	"time"

	gmailv1 "google.golang.org/api/gmail/v1"
)

// Message holds attachment data downloaded from Gmail.
type Message struct {
	ID          string
	Subject     string
	Sender      string
	Date        time.Time
	Attachments []Attachment
}

// Attachment holds a single attachment.
type Attachment struct {
	Filename string
	MIMEType string
	Data     []byte
}

// SearchMessages searches Gmail for messages matching query and returns their IDs.
func SearchMessages(ctx context.Context, svc *gmailv1.Service, query string) ([]string, error) {
	var ids []string
	var pageToken string
	for {
		req := svc.Users.Messages.List("me").Q(query).Context(ctx)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		res, err := req.Do()
		if err != nil {
			return nil, fmt.Errorf("list messages: %w", err)
		}
		for _, m := range res.Messages {
			ids = append(ids, m.Id)
		}
		if res.NextPageToken == "" {
			break
		}
		pageToken = res.NextPageToken
	}
	return ids, nil
}

// FetchMessage downloads a full message and its attachments.
func FetchMessage(ctx context.Context, svc *gmailv1.Service, msgID string) (*Message, error) {
	raw, err := svc.Users.Messages.Get("me", msgID).Format("raw").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get message %s: %w", msgID, err)
	}

	data, err := base64.RawURLEncoding.DecodeString(raw.Raw)
	if err != nil {
		return nil, fmt.Errorf("decode raw: %w", err)
	}

	em, err := mail.ReadMessage(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	subject := decodeHeader(em.Header.Get("Subject"))
	from := decodeHeader(em.Header.Get("From"))
	dateStr := em.Header.Get("Date")
	var date time.Time
	if d, err := mail.ParseDate(dateStr); err == nil {
		date = d
	}

	msg := &Message{
		ID:      msgID,
		Subject: subject,
		Sender:  from,
		Date:    date,
	}

	full, err := svc.Users.Messages.Get("me", msgID).Format("full").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get full message %s: %w", msgID, err)
	}

	walkParts(ctx, svc, msgID, full.Payload, msg)
	return msg, nil
}

func walkParts(ctx context.Context, svc *gmailv1.Service, msgID string, part *gmailv1.MessagePart, msg *Message) {
	if part == nil {
		return
	}
	for _, h := range part.Headers {
		if strings.EqualFold(h.Name, "Content-Disposition") && strings.Contains(h.Value, "attachment") {
			filename := filenameFromPart(part)
			if filename == "" {
				filename = "attachment"
			}
			var attData []byte
			if part.Body != nil && part.Body.Data != "" {
				d, err := base64.RawURLEncoding.DecodeString(part.Body.Data)
				if err == nil {
					attData = d
				}
			} else if part.Body != nil && part.Body.AttachmentId != "" {
				att, err := svc.Users.Messages.Attachments.Get("me", msgID, part.Body.AttachmentId).Context(ctx).Do()
				if err != nil {
					log.Printf("fetch attachment %s: %v", part.Body.AttachmentId, err)
					continue
				}
				d, err := base64.RawURLEncoding.DecodeString(att.Data)
				if err == nil {
					attData = d
				}
			}
			if attData != nil {
				msg.Attachments = append(msg.Attachments, Attachment{
					Filename: filename,
					MIMEType: part.MimeType,
					Data:     attData,
				})
			}
			return
		}
	}
	for _, p := range part.Parts {
		walkParts(ctx, svc, msgID, p, msg)
	}
}

func filenameFromPart(part *gmailv1.MessagePart) string {
	for _, h := range part.Headers {
		if strings.EqualFold(h.Name, "Content-Disposition") {
			_, params, err := mime.ParseMediaType(h.Value)
			if err == nil {
				if fn, ok := params["filename"]; ok {
					return fn
				}
			}
		}
	}
	return part.Filename
}

func decodeHeader(s string) string {
	dec := new(mime.WordDecoder)
	out, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return out
}

// Client abstracts Gmail API calls for testability.
type Client interface {
	SearchMessages(ctx context.Context, query string) ([]string, error)
	FetchMessage(ctx context.Context, msgID string) (*Message, error)
	TrashMessage(ctx context.Context, msgID string) error
}

// NewClient wraps a *gmailv1.Service in the Client interface.
func NewClient(svc *gmailv1.Service) Client {
	return &serviceClient{svc: svc}
}

type serviceClient struct{ svc *gmailv1.Service }

func (c *serviceClient) SearchMessages(ctx context.Context, query string) ([]string, error) {
	return SearchMessages(ctx, c.svc, query)
}

func (c *serviceClient) FetchMessage(ctx context.Context, msgID string) (*Message, error) {
	return FetchMessage(ctx, c.svc, msgID)
}

func (c *serviceClient) TrashMessage(ctx context.Context, msgID string) error {
	_, err := c.svc.Users.Messages.Trash("me", msgID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("trash message %s: %w", msgID, err)
	}
	return nil
}
