package handlers

import (
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/session"
)

// maxReportedReleases is how many of the latest releases a window report
// lists. The rest are only counted.
const maxReportedReleases = 5

// windowLog is what the approver has been shown about one approval window, and
// on which message. Its lock is held across the Telegram calls that update the
// report, so the releases of one window are reported one at a time, in order.
type windowLog struct {
	expiresAt time.Time // fixed when the log starts, read without mu

	mu        sync.Mutex
	messageID int // message that shows the report, zero when there is none
	report    models.WindowReport
}

// windowLogs holds the log of every approval window that is still open.
type windowLogs struct {
	mu   sync.Mutex
	logs map[string]*windowLog
}

func newWindowLogs() *windowLogs {
	return &windowLogs{logs: make(map[string]*windowLog)}
}

// open starts the log of a window whose report is on messageID, and forgets
// windows that ran out. A window that ended early keeps its log until it would
// have run out; nothing is released under it, so nothing reads it.
func (w *windowLogs) open(messageID int, report models.WindowReport) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	for id, log := range w.logs {
		if now.After(log.expiresAt) {
			delete(w.logs, id)
		}
	}
	w.logs[report.SessionID] = &windowLog{expiresAt: report.ExpiresAt, messageID: messageID, report: report}
}

// get returns the log of sess. A window with no log, such as one forgotten the
// moment it ran out, gets an empty one, whose report goes to a new message.
func (w *windowLogs) get(sess session.Session) *windowLog {
	w.mu.Lock()
	defer w.mu.Unlock()

	log, ok := w.logs[sess.ID]
	if !ok {
		log = &windowLog{
			expiresAt: sess.ExpiresAt,
			report:    models.WindowReport{SessionID: sess.ID, Machine: sess.Machine, ExpiresAt: sess.ExpiresAt},
		}
		w.logs[sess.ID] = log
	}
	return log
}

// reportRelease shows the approver req as released under sess, then checks that
// token still opens the window. It returns the message the report is on, and
// whether the window was still open. When it was not, the approver ended it
// while the report was on its way: the report is taken back, and req has to be
// asked about instead.
//
// A release that cannot be shown returns an error, and must not happen.
func (h *Handler) reportRelease(sess session.Session, token string, req *models.ApprovalRequest) (int, bool, error) {
	log := h.windows.get(sess)
	log.mu.Lock()
	defer log.mu.Unlock()

	entry := *req
	entry.Token = ""
	entry.SessionToken = ""
	next := log.report
	next.Released++
	next.Recent = append([]models.ApprovalRequest{entry}, log.report.Recent...)
	if len(next.Recent) > maxReportedReleases {
		next.Recent = next.Recent[:maxReportedReleases]
	}

	messageID, err := h.showReport(log, &next)
	if err != nil {
		return 0, false, err
	}

	if _, open := h.sessions.Lookup(token); !open {
		if err := h.notifier.UpdateWindowReport(messageID, &log.report); err != nil {
			h.log.Error("Failed to take back the release from the approval window report", logger.F("error", err.Error(), "request_id", req.ID, "session_id", sess.ID))
		}
		return messageID, false, nil
	}

	log.report = next
	return messageID, true, nil
}

// showReport puts report on the message of log, which the caller holds. When
// that message cannot be edited, as when the approver deleted it, the report
// moves to a new message, and later reports go there.
func (h *Handler) showReport(log *windowLog, report *models.WindowReport) (int, error) {
	if log.messageID != 0 {
		err := h.notifier.UpdateWindowReport(log.messageID, report)
		if err == nil {
			return log.messageID, nil
		}
		h.log.Error("Failed to update the approval window report, moving it to a new message", logger.F("error", err.Error(), "session_id", report.SessionID, "message_id", log.messageID))
	}

	report.Moved = true
	messageID, err := h.notifier.SendWindowReport(report)
	if err != nil {
		return 0, err
	}
	log.messageID = messageID
	log.report.Moved = true
	return messageID, nil
}
