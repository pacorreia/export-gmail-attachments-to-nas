package scheduler

import (
	"context"
	"encoding/json"
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
	"gorm.io/gorm/clause"
)

// Default is the global Scheduler instance, available after Start returns.
var Default *Scheduler

// Scheduler manages background rule-execution goroutines.
type Scheduler struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	rules  map[uint]context.CancelFunc // per-rule cancel functions
}

// Start launches goroutines for all enabled rule/account/fileshare assignments
// and sets Default to the returned Scheduler.
func Start(ctx context.Context) *Scheduler {
	ctx, cancel := context.WithCancel(ctx)
	s := &Scheduler{
		ctx:    ctx,
		cancel: cancel,
		rules:  make(map[uint]context.CancelFunc),
	}

	var rules []models.Rule
	db.DB.Where("enabled = ?", true).Find(&rules)
	for _, rule := range rules {
		s.startRule(rule)
	}
	Default = s
	return s
}

// startRule loads assignments for rule and launches runLoop goroutines.
// A per-rule context is stored in s.rules so goroutines can be individually cancelled.
func (s *Scheduler) startRule(rule models.Rule) {
	var assignments []models.RuleAssignment
	db.DB.Where("rule_id = ?", rule.ID).Find(&assignments)

	accountIDs := map[uint]struct{}{}
	fileShareIDs := map[uint]struct{}{}
	for _, a := range assignments {
		accountIDs[a.AccountID] = struct{}{}
		fileShareIDs[a.FileShareID] = struct{}{}
	}
	if len(accountIDs) == 0 {
		return
	}

	ruleCtx, ruleCancel := context.WithCancel(s.ctx)
	s.mu.Lock()
	s.rules[rule.ID] = ruleCancel
	s.mu.Unlock()

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
		go s.runLoop(ruleCtx, rule, acct, shares)
	}
}

// Reload cancels existing goroutines for ruleID and restarts them if the rule is enabled.
// Call this after creating or updating a rule.
func (s *Scheduler) Reload(ruleID uint) {
	s.mu.Lock()
	if cancel, ok := s.rules[ruleID]; ok {
		cancel()
		delete(s.rules, ruleID)
	}
	s.mu.Unlock()

	var rule models.Rule
	if err := db.DB.First(&rule, ruleID).Error; err != nil || !rule.Enabled {
		return
	}
	s.startRule(rule)
}

// StopRule cancels and removes the goroutines for a rule (e.g. on deletion or disable).
func (s *Scheduler) StopRule(ruleID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.rules[ruleID]; ok {
		cancel()
		delete(s.rules, ruleID)
	}
}

// RunRuleNow triggers an immediate execution of the given rule for all its
// account/fileshare assignments. Jobs run in background goroutines and the
// function returns immediately (fire-and-forget). Returns an error only if
// the rule is not found.
func RunRuleNow(ruleID uint) error {
	var rule models.Rule
	if err := db.DB.First(&rule, ruleID).Error; err != nil {
		return err
	}

	var assignments []models.RuleAssignment
	db.DB.Where("rule_id = ?", rule.ID).Find(&assignments)

	accountIDs := map[uint]struct{}{}
	fileShareIDs := map[uint]struct{}{}
	for _, a := range assignments {
		accountIDs[a.AccountID] = struct{}{}
		fileShareIDs[a.FileShareID] = struct{}{}
	}

	ctx := context.Background()
	if Default != nil {
		ctx = Default.ctx
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
		go runSingleJob(ctx, rule, acct, shares)
	}
	return nil
}

// ResetCheckpoint deletes the sync checkpoint for a rule so the next run processes all matching messages.
func ResetCheckpoint(ruleID uint) error {
	return db.DB.Where("rule_id = ?", ruleID).Delete(&models.SyncCheckpoint{}).Error
}

// Stop cancels all goroutines and waits for them to finish.
func (s *Scheduler) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *Scheduler) runLoop(ctx context.Context, rule models.Rule, acct models.Account, shares []models.FileShare) {
	defer s.wg.Done()

	// Interval-type schedules run immediately on first start.
	if isIntervalSchedule(rule.Schedule) {
		runSingleJob(ctx, rule, acct, shares)
	}

	for {
		next, stopAfter := nextRunFromSchedule(rule.Schedule, time.Now())
		if next.IsZero() {
			return // no future runs (once-executed or until-expired)
		}
		delay := time.Until(next)
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
		if ctx.Err() != nil {
			return
		}
		runSingleJob(ctx, rule, acct, shares)
		if stopAfter {
			return
		}
	}
}

// scheduleJSON is the structured schedule stored as a JSON string in Rule.Schedule.
type scheduleJSON struct {
	Type       string `json:"type"`         // interval | daily | weekly | monthly | once
	Interval   string `json:"interval"`     // Go duration string, used when Type == "interval"
	Days       []int  `json:"days"`         // 0=Sun..6=Sat, used when Type == "weekly"
	DayOfMonth int    `json:"day_of_month"` // 1-31, used when Type == "monthly"
	Hour       int    `json:"hour"`         // 0-23, used with daily/weekly/monthly
	Minute     int    `json:"minute"`       // 0-59, used with daily/weekly/monthly
	OnceAt     string `json:"once_at"`      // "2006-01-02T15:04", used when Type == "once"
	Until      string `json:"until"`        // "2006-01-02", optional end date
}

// isIntervalSchedule reports whether the schedule is a plain duration string or
// an explicit interval-type JSON object (both of which should run immediately on start).
func isIntervalSchedule(sched string) bool {
	if !strings.HasPrefix(sched, "{") {
		return true
	}
	var s struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal([]byte(sched), &s)
	return s.Type == "interval" || s.Type == ""
}

// nextRunFromSchedule returns (when to run next, stopAfterRun).
// A zero Time means there is no next run (scheduler goroutine should exit).
func nextRunFromSchedule(sched string, now time.Time) (time.Time, bool) {
	if !strings.HasPrefix(sched, "{") {
		// Legacy duration string – wait interval then run.
		return now.Add(parseSchedule(sched)), false
	}
	var s scheduleJSON
	if err := json.Unmarshal([]byte(sched), &s); err != nil {
		log.Printf("invalid schedule JSON %q: %v", sched, err)
		return now.Add(intervalFromSetting()), false
	}
	// Check optional until date.
	if s.Until != "" {
		until, err := time.ParseInLocation("2006-01-02", s.Until, time.Local)
		if err == nil && now.After(until.AddDate(0, 0, 1)) {
			return time.Time{}, false // past until date
		}
	}
	switch s.Type {
	case "interval":
		return now.Add(parseSchedule(s.Interval)), false
	case "daily":
		return nextTimeOfDay(now, s.Hour, s.Minute), false
	case "weekly":
		return nextWeekday(now, s.Days, s.Hour, s.Minute), false
	case "monthly":
		return nextMonthDay(now, s.DayOfMonth, s.Hour, s.Minute), false
	case "once":
		t, err := time.ParseInLocation("2006-01-02T15:04", s.OnceAt, time.Local)
		if err != nil || now.After(t) {
			return time.Time{}, true // bad format or already past
		}
		return t, true // run once then stop
	default:
		return now.Add(intervalFromSetting()), false
	}
}

func nextTimeOfDay(after time.Time, hour, minute int) time.Time {
	next := time.Date(after.Year(), after.Month(), after.Day(), hour, minute, 0, 0, after.Location())
	if !next.After(after) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

func nextWeekday(after time.Time, days []int, hour, minute int) time.Time {
	if len(days) == 0 {
		return nextTimeOfDay(after, hour, minute)
	}
	daySet := make(map[time.Weekday]bool, len(days))
	for _, d := range days {
		daySet[time.Weekday(d)] = true
	}
	for i := 0; i <= 7; i++ {
		candidate := after.AddDate(0, 0, i)
		if daySet[candidate.Weekday()] {
			t := time.Date(candidate.Year(), candidate.Month(), candidate.Day(), hour, minute, 0, 0, candidate.Location())
			if t.After(after) {
				return t
			}
		}
	}
	return nextTimeOfDay(after, hour, minute)
}

func nextMonthDay(after time.Time, dayOfMonth, hour, minute int) time.Time {
	candidate := time.Date(after.Year(), after.Month(), dayOfMonth, hour, minute, 0, 0, after.Location())
	if candidate.After(after) && candidate.Month() == after.Month() {
		return candidate
	}
	// Roll to next month.
	nm := after.AddDate(0, 1, 0)
	return time.Date(nm.Year(), nm.Month(), dayOfMonth, hour, minute, 0, 0, after.Location())
}

// parseSchedule converts a schedule string to a time.Duration.
// Supports standard Go duration strings (e.g. "30m", "1h", "24h") plus a "d"
// suffix for days (e.g. "7d"). An empty string falls back to the global
// scheduler_interval_minutes setting.
func parseSchedule(s string) time.Duration {
	if s == "" {
		return intervalFromSetting()
	}
	// Support "d" suffix for days (not natively supported by time.ParseDuration).
	if strings.HasSuffix(s, "d") {
		var n int
		fmt.Sscanf(strings.TrimSuffix(s, "d"), "%d", &n)
		if n > 0 {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Printf("invalid schedule %q, falling back to global setting", s)
		return intervalFromSetting()
	}
	return d
}

// intervalFromSetting reads the scheduler interval from the DB settings.
// Defaults to 60 minutes if not set or invalid.
func intervalFromSetting() time.Duration {
	var mins int
	fmt.Sscanf(db.GetSetting("scheduler_interval_minutes", ""), "%d", &mins)
	if mins > 0 {
		return time.Duration(mins) * time.Minute
	}
	return 60 * time.Minute
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

	client, err := gmail.GmailServiceForAccount(ctx, &acct)
	if err != nil {
		fail(fmt.Errorf("auth: %w", err))
		return
	}

	// Apply sync checkpoint: only process messages newer than the last successful run.
	query := rule.GmailQuery
	var cp models.SyncCheckpoint
	if db.DB.Where("rule_id = ? AND account_id = ?", rule.ID, acct.ID).Limit(1).Find(&cp).RowsAffected > 0 {
		query = fmt.Sprintf("%s after:%d", query, cp.SyncedAt.Unix())
		logger.Printf("checkpoint at %s, restricting query with after:%d", cp.SyncedAt.Format(time.RFC3339), cp.SyncedAt.Unix())
	}

	ids, err := client.SearchMessages(ctx, query)
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
		msg, err := client.FetchMessage(ctx, id)
		if err != nil {
			logger.Printf("fetch %s: %v", id, err)
			continue
		}
		saved := processMessage(ctx, msg, rule, acct, shares, logger, openShare, pdf.Default)
		msgCount += saved
		if saved > 0 && rule.DeleteAfterExport {
			if trashErr := client.TrashMessage(ctx, id); trashErr != nil {
				logger.Printf("trash %s: %v", id, trashErr)
			} else {
				logger.Printf("trashed message %s", id)
			}
		}
	}

	now := time.Now()
	db.DB.Model(&acct).Update("last_sync_at", now)

	// Upsert sync checkpoint so subsequent runs only fetch new messages.
	db.DB.Clauses(clause.OnConflict{UpdateAll: true}).Create(&models.SyncCheckpoint{
		RuleID:    rule.ID,
		AccountID: acct.ID,
		SyncedAt:  now,
	})

	logEntry.FinishedAt = &now
	logEntry.Status = "success"
	logEntry.MessageCount = msgCount
	db.DB.Save(&logEntry)
}

// processMessage saves all attachments from one email to all assigned file shares.
// Returns the number of attachments successfully saved.
// openBackend is injected so callers (and tests) can control which backend is used.
func processMessage(ctx context.Context, msg *gmail.Message, rule models.Rule, acct models.Account, shares []models.FileShare, logger *log.Logger, openBackend func(models.FileShare) fsiface.FileShare, pdfConv pdf.Converter) int {
	subdir := expandTemplate(rule.SubfolderTemplate, msg)
	count := 0
	for _, att := range msg.Attachments {
		relPath := filepath.Join(subdir, att.Filename)
		for _, share := range shares {
			backend := openBackend(share)
			if backend == nil {
				continue
			}
			if err := saveAttachmentToBackend(ctx, att.Data, relPath, backend, logger); err == nil {
				count++
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
				convertAndSaveImages(ctx, att, subdir, share, logger, openBackend, pdfConv)
			}
		}
	}
	return count
}

// saveAttachmentToBackend writes a single attachment to a file share backend.
func saveAttachmentToBackend(ctx context.Context, data []byte, relPath string, backend fsiface.FileShare, logger *log.Logger) error {
	if err := backend.Write(ctx, relPath, data); err != nil {
		logger.Printf("write %s: %v", relPath, err)
		return err
	}
	logger.Printf("saved %s", relPath)
	return nil
}

// convertAndSaveImages converts a PDF attachment to page images and saves them to a share.
func convertAndSaveImages(ctx context.Context, att gmail.Attachment, subdir string, share models.FileShare, logger *log.Logger, openBackend func(models.FileShare) fsiface.FileShare, pdfConv pdf.Converter) {
	images, err := pdfConv.ConvertToImages(ctx, att.Filename, att.Data, 150)
	if err != nil {
		logger.Printf("pdf convert %s: %v", att.Filename, err)
		return
	}
	backend := openBackend(share)
	if backend == nil {
		return
	}
	defer backend.Close()
	for _, img := range images {
		imgPath := filepath.Join(subdir, img.Name)
		if err := backend.Write(ctx, imgPath, img.Data); err != nil {
			logger.Printf("write png %s: %v", imgPath, err)
		}
	}
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
