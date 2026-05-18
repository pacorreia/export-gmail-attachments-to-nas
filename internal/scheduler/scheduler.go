package scheduler

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	fsiface "github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare/local"
	fsmb "github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare/smb"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/gmail"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/pdf"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin"
)

// Scheduler manages background rule-execution goroutines.
type Scheduler struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Start launches goroutines for all enabled rule/account/fileshare assignments.
func Start(ctx context.Context) *Scheduler {
	ctx, cancel := context.WithCancel(ctx)
	s := &Scheduler{cancel: cancel}

	var rules []models.Rule
	db.DB.Where("enabled = ?", true).Find(&rules)

	for _, rule := range rules {
		var assignments []models.RuleAssignment
		db.DB.Where("rule_id = ?", rule.ID).Find(&assignments)

		accountIDs := map[uint]struct{}{}
		fileShareIDs := map[uint]struct{}{}
		for _, a := range assignments {
			accountIDs[a.AccountID] = struct{}{}
			fileShareIDs[a.FileShareID] = struct{}{}
		}

		for aID := range accountIDs {
			var acct models.Account
			if err := db.DB.First(&acct, aID).Error; err != nil {
				continue
			}
			var shares []models.FileShare
			for fsID := range fileShareIDs {
				var fs models.FileShare
				if err := db.DB.First(&fs, fsID).Error; err == nil {
					shares = append(shares, fs)
				}
			}
			s.wg.Add(1)
			go s.runLoop(ctx, rule, acct, shares)
		}
	}
	return s
}

// Stop cancels all goroutines and waits for them to finish.
func (s *Scheduler) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *Scheduler) runLoop(ctx context.Context, rule models.Rule, acct models.Account, shares []models.FileShare) {
	defer s.wg.Done()

	interval := 60 * time.Minute
	var setting models.Setting
	if err := db.DB.Where("key = ?", "scheduler_interval_minutes").First(&setting).Error; err == nil {
		var mins int
		fmt.Sscanf(setting.Value, "%d", &mins)
		if mins > 0 {
			interval = time.Duration(mins) * time.Minute
		}
	}

	for {
		runSingleJob(ctx, rule, acct, shares)

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func runSingleJob(ctx context.Context, rule models.Rule, acct models.Account, shares []models.FileShare) {
	logger := log.New(log.Writer(), fmt.Sprintf("[rule:%d acct:%d] ", rule.ID, acct.ID), log.LstdFlags)

	logEntry := models.RunLog{
		RuleID:    rule.ID,
		AccountID: acct.ID,
		StartedAt: time.Now(),
		Status:    "running",
	}
	db.DB.Create(&logEntry)

	fail := func(err error) {
		now := time.Now()
		logEntry.FinishedAt = &now
		logEntry.Status = "error"
		logEntry.Error = err.Error()
		db.DB.Save(&logEntry)
	}

	svc, err := gmail.GmailServiceForAccount(ctx, &acct)
	if err != nil {
		fail(fmt.Errorf("auth: %w", err))
		return
	}

	ids, err := gmail.SearchMessages(ctx, svc, rule.GmailQuery)
	if err != nil {
		fail(fmt.Errorf("search: %w", err))
		return
	}
	logger.Printf("found %d messages", len(ids))

	msgCount := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		msg, err := gmail.FetchMessage(ctx, svc, id)
		if err != nil {
			logger.Printf("fetch %s: %v", id, err)
			continue
		}
		for _, att := range msg.Attachments {
			subdir := expandTemplate(rule.SubfolderTemplate, msg)

			for _, share := range shares {
				backend := openShare(share)
				if backend == nil {
					continue
				}

				relPath := filepath.Join(subdir, att.Filename)
				if err := backend.Write(ctx, relPath, att.Data); err != nil {
					logger.Printf("write %s: %v", relPath, err)
				} else {
					logger.Printf("saved %s", relPath)
					msgCount++
					plugin.Dispatch(ctx, plugin.AttachmentEvent{
						RuleID:      int64(rule.ID),
						AccountID:   int64(acct.ID),
						FileShareID: int64(share.ID),
						Filename:    att.Filename,
						NASPath:     relPath,
						SizeBytes:   int64(len(att.Data)),
						EmailDate:   msg.Date,
						Subject:     msg.Subject,
						Sender:      msg.Sender,
						MIMEType:    att.MIMEType,
					})
				}
				backend.Close()

				if rule.ConvertPDFToImage && strings.ToLower(filepath.Ext(att.Filename)) == ".pdf" {
					images, err := pdf.ConvertToImages(ctx, att.Filename, att.Data, 150)
					if err != nil {
						logger.Printf("pdf convert %s: %v", att.Filename, err)
						continue
					}
					backend2 := openShare(share)
					if backend2 == nil {
						continue
					}
					for _, img := range images {
						imgName := string(img[0])
						imgData := img[1]
						imgPath := filepath.Join(subdir, imgName)
						if err := backend2.Write(ctx, imgPath, imgData); err != nil {
							logger.Printf("write png %s: %v", imgPath, err)
						}
					}
					backend2.Close()
				}
			}
		}
	}

	now := time.Now()
	db.DB.Model(&acct).Update("last_sync_at", now)

	logEntry.FinishedAt = &now
	logEntry.Status = "success"
	logEntry.MessageCount = msgCount
	db.DB.Save(&logEntry)
}

func openShare(share models.FileShare) fsiface.FileShare {
	switch share.Type {
	case "local":
		return local.New(share.BasePath)
	case "smb":
		password := ""
		if share.PasswordEnc != "" {
			dec, err := crypto.Decrypt(share.PasswordEnc)
			if err == nil {
				password = dec
			}
		}
		return fsmb.New(share.Host, share.Share, share.Username, password)
	}
	return nil
}

func expandTemplate(tmpl string, msg *gmail.Message) string {
	if tmpl == "" {
		return ""
	}
	r := strings.NewReplacer(
		"{year}", fmt.Sprintf("%04d", msg.Date.Year()),
		"{month}", fmt.Sprintf("%02d", int(msg.Date.Month())),
		"{day}", fmt.Sprintf("%02d", msg.Date.Day()),
		"{sender}", sanitize(msg.Sender),
		"{subject}", sanitize(msg.Subject),
	)
	return r.Replace(tmpl)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
