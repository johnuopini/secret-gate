package telegram

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

// sentCall is one request the client made to the Bot API.
type sentCall struct {
	Method string
	Body   map[string]any
}

// recordingAPI answers every Bot API call with success and keeps what was sent.
func recordingAPI(t *testing.T) (*Client, *[]sentCall) {
	t.Helper()

	var calls []sentCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		calls = append(calls, sentCall{Method: r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], Body: body})
		w.Write([]byte(`{"ok":true,"result":{"message_id":77,"chat":{"id":42}}}`))
	}))
	t.Cleanup(srv.Close)

	c := New(testToken, 42)
	c.baseURL = srv.URL + "/bot" + testToken
	return c, &calls
}

// buttonData returns the callback data of every button on a sent message.
func buttonData(t *testing.T, call sentCall) []string {
	t.Helper()

	markup, ok := call.Body["reply_markup"].(map[string]any)
	if !ok {
		return nil
	}
	var data []string
	for _, row := range markup["inline_keyboard"].([]any) {
		for _, button := range row.([]any) {
			data = append(data, button.(map[string]any)["callback_data"].(string))
		}
	}
	return data
}

func testRequest() *models.ApprovalRequest {
	return &models.ApprovalRequest{
		ID:               "0123456789abcdef0123456789abcdef",
		SecretName:       "db",
		Vault:            "HomeLab",
		RequesterMachine: "devvm",
		RequesterIP:      "10.0.0.7",
		Reason:           "deploy",
		ExpiresAt:        time.Now().Add(15 * time.Minute),
	}
}

func TestSendApprovalRequest_OffersTheWindowOnlyWhenTheRequestAllowsIt(t *testing.T) {
	t.Run("offered", func(t *testing.T) {
		c, calls := recordingAPI(t)
		req := testRequest()
		req.SessionTTL = 8 * time.Hour

		if _, err := c.SendApprovalRequest(req, ""); err != nil {
			t.Fatalf("SendApprovalRequest: %v", err)
		}

		got := buttonData(t, (*calls)[0])
		want := []string{"approve:" + req.ID, "deny:" + req.ID, "session:" + req.ID}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("buttons = %v, want %v", got, want)
		}
		if !strings.Contains((*calls)[0].Body["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[1].([]any)[0].(map[string]any)["text"].(string), "8h") {
			t.Error("the window button does not say how long the window lasts")
		}
	})

	t.Run("not offered", func(t *testing.T) {
		c, calls := recordingAPI(t)
		req := testRequest()

		if _, err := c.SendApprovalRequest(req, ""); err != nil {
			t.Fatalf("SendApprovalRequest: %v", err)
		}

		got := buttonData(t, (*calls)[0])
		want := []string{"approve:" + req.ID, "deny:" + req.ID}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("buttons = %v, want %v", got, want)
		}
	})
}

func TestUpdateMessageApproved_WithAWindow_CarriesTheEndButton(t *testing.T) {
	c, calls := recordingAPI(t)
	req := testRequest()
	req.SessionID = "fedcba9876543210fedcba9876543210"
	req.SessionExpiresAt = time.Now().Add(8 * time.Hour)

	if err := c.UpdateMessageApproved(77, req, "franz"); err != nil {
		t.Fatalf("UpdateMessageApproved: %v", err)
	}

	got := buttonData(t, (*calls)[0])
	if len(got) != 1 || got[0] != "endsession:"+req.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	if !strings.Contains((*calls)[0].Body["text"].(string), "Approval window") {
		t.Error("the approved message does not mention the approval window")
	}
}

func TestUpdateMessageApproved_WithoutAWindow_HasNoButtons(t *testing.T) {
	c, calls := recordingAPI(t)

	if err := c.UpdateMessageApproved(77, testRequest(), "franz"); err != nil {
		t.Fatalf("UpdateMessageApproved: %v", err)
	}

	if got := buttonData(t, (*calls)[0]); len(got) != 0 {
		t.Errorf("buttons = %v, want none", got)
	}
}

// testReport is the report of a window opened by testRequest and approved by
// franz, with released requests released so far and recent the latest of them.
func testReport(released int, recent ...models.ApprovalRequest) *models.WindowReport {
	opened := testRequest()
	opened.SessionID = "fedcba9876543210fedcba9876543210"
	opened.SessionExpiresAt = time.Now().Add(8 * time.Hour)
	return &models.WindowReport{
		SessionID: opened.SessionID,
		Machine:   opened.RequesterMachine,
		ExpiresAt: opened.SessionExpiresAt,
		Opened:    opened,
		Approver:  "franz",
		Released:  released,
		Recent:    recent,
	}
}

// release is a request from the window's machine for secret, sent from ip.
func release(secret, ip, reason string) models.ApprovalRequest {
	req := *testRequest()
	req.SecretName = secret
	req.RequesterIP = ip
	req.Reason = reason
	return req
}

func TestUpdateWindowReport_EditsTheMessageWithTheReleases(t *testing.T) {
	c, calls := recordingAPI(t)
	var recent []models.ApprovalRequest
	for _, secret := range []string{"s1", "s2", "s3", "s4", "s5"} {
		recent = append(recent, release(secret, "10.0.0.7", "reason of "+secret))
	}
	report := testReport(7, recent...)

	if err := c.UpdateWindowReport(77, report); err != nil {
		t.Fatalf("UpdateWindowReport: %v", err)
	}

	call := (*calls)[0]
	if call.Method != "editMessageText" || call.Body["message_id"] != float64(77) {
		t.Errorf("sent %s for message %v, want editMessageText for message 77", call.Method, call.Body["message_id"])
	}
	if got := buttonData(t, call); len(got) != 1 || got[0] != "endsession:"+report.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	text := call.Body["text"].(string)
	for _, want := range []string{"Released under this window:</b> 7", "s1", "s5", "reason of s3"} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not show %q:\n%s", want, text)
		}
	}
	if lines := strings.Count(text, "\n• "); lines != 5 {
		t.Errorf("report lists %d releases, want 5:\n%s", lines, text)
	}
}

func TestUpdateMessageApproved_WithAWindow_ShowsTheEmptyReport(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(0)

	c.UpdateMessageApproved(77, report.Opened, "franz")
	c.UpdateWindowReport(77, report)

	approved, empty := (*calls)[0].Body["text"].(string), (*calls)[1].Body["text"].(string)
	if approved != empty {
		t.Errorf("the approved message:\n%s\nis not the report of a window with no releases:\n%s", approved, empty)
	}
	if !strings.Contains(approved, "Released under this window:</b> none yet") {
		t.Errorf("the approved message does not say nothing was released yet:\n%s", approved)
	}
}

func TestSendWindowReport_IsSilentAndCarriesTheEndButton(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(1, release("db", "10.0.0.7", "deploy"))

	msgID, err := c.SendWindowReport(report)
	if err != nil {
		t.Fatalf("SendWindowReport: %v", err)
	}

	call := (*calls)[0]
	if msgID != 77 || call.Method != "sendMessage" {
		t.Errorf("sent %s returning message %d, want sendMessage returning 77", call.Method, msgID)
	}
	if call.Body["disable_notification"] != true {
		t.Error("the moved report is not silent")
	}
	if got := buttonData(t, call); len(got) != 1 || got[0] != "endsession:"+report.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	text := call.Body["text"].(string)
	for _, want := range []string{"db", "devvm", "deploy", "could not be updated"} {
		if !strings.Contains(text, want) {
			t.Errorf("moved report does not show %q:\n%s", want, text)
		}
	}
}

func TestUpdateWindowReport_OfAMovedReport_KeepsSayingWhyItMoved(t *testing.T) {
	c, calls := recordingAPI(t)
	moved := testReport(2, release("db", "10.0.0.7", "deploy"))
	moved.Moved = true

	c.UpdateWindowReport(77, testReport(1, release("db", "10.0.0.7", "deploy")))
	c.UpdateWindowReport(78, moved)

	if text := (*calls)[0].Body["text"].(string); strings.Contains(text, "could not be updated") {
		t.Errorf("the report in the approval message says it moved:\n%s", text)
	}
	if text := (*calls)[1].Body["text"].(string); !strings.Contains(text, "could not be updated") {
		t.Errorf("the moved report no longer says why it moved:\n%s", text)
	}
}

func TestWindowReport_LongReasonAndBigBatch_StayShort(t *testing.T) {
	c, calls := recordingAPI(t)

	batch := release("", "10.0.0.7", strings.Repeat("x", 500))
	for i := range 20 {
		batch.Secrets = append(batch.Secrets, models.SecretRequest{SecretName: fmt.Sprintf("alpha%02d", i), Vault: strings.Repeat("v", 500)})
	}
	report := testReport(5, batch, batch, batch, batch, batch)
	// An opening batch too big to repeat in full.
	for i := range 60 {
		report.Opened.Secrets = append(report.Opened.Secrets, models.SecretRequest{SecretName: strings.Repeat("n", 50) + fmt.Sprint(i)})
	}

	c.UpdateWindowReport(77, report)

	text := (*calls)[0].Body["text"].(string)
	if strings.Contains(text, strings.Repeat("x", 81)) {
		t.Error("a release shows more than 80 characters of its reason")
	}
	if strings.Contains(text, strings.Repeat("v", 41)) {
		t.Error("a release shows more than 40 characters of a vault")
	}
	if !strings.Contains(text, "alpha00") || !strings.Contains(text, "alpha19") || strings.Contains(text, "more") {
		t.Errorf("the latest release does not list all 20 of its secrets:\n%s", text)
	}
	// Telegram rejects messages over 4096 characters.
	if len(text) > 4096 {
		t.Errorf("report is %d bytes, Telegram allows 4096 characters", len(text))
	}
}

func TestWindowReport_ListsEverySecretOfAReleasedBatch(t *testing.T) {
	c, calls := recordingAPI(t)
	batch := release("", "10.0.0.7", "deploy")
	for i := range 8 {
		batch.Secrets = append(batch.Secrets, models.SecretRequest{SecretName: fmt.Sprintf("alpha%02d", i), Vault: "Dev"})
	}

	c.UpdateWindowReport(77, testReport(1, batch))

	text := (*calls)[0].Body["text"].(string)
	for i := range 8 {
		if want := fmt.Sprintf("<code>alpha%02d</code> in <code>Dev</code>", i); !strings.Contains(text, want) {
			t.Errorf("report does not show %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "more") {
		t.Errorf("report hides part of the batch:\n%s", text)
	}
}

func TestWindowReport_TooLong_DropsOlderReleasesBeforeTheLatest(t *testing.T) {
	c, calls := recordingAPI(t)
	batch := func(prefix string) models.ApprovalRequest {
		r := release("", "10.0.0.7", "deploy")
		for i := range 20 {
			r.Secrets = append(r.Secrets, models.SecretRequest{SecretName: fmt.Sprintf("%s%02d-%s", prefix, i, strings.Repeat("n", 30))})
		}
		return r
	}

	c.UpdateWindowReport(77, testReport(9, batch("new"), batch("old"), batch("old"), batch("old"), batch("old")))

	text := (*calls)[0].Body["text"].(string)
	if len(text) > 4096 {
		t.Fatalf("report is %d bytes, Telegram allows 4096 characters", len(text))
	}
	for i := range 20 {
		if want := fmt.Sprintf("new%02d", i); !strings.Contains(text, want) {
			t.Errorf("the latest release does not show %q:\n%s", want, text)
		}
	}
	if lines := strings.Count(text, "\n• "); lines >= 5 {
		t.Errorf("report lists %d releases, want older ones left out to fit:\n%s", lines, text)
	}
	if want := fmt.Sprintf("Released under this window:</b> 9, latest %d:", strings.Count(text, "\n• ")); !strings.Contains(text, want) {
		t.Errorf("report does not say %q:\n%s", want, text)
	}
}

func TestWindowReport_ThatCannotShowTheLatestReleaseInFull_IsNotSent(t *testing.T) {
	huge := release("", "10.0.0.7", "deploy")
	for i := range 200 {
		huge.Secrets = append(huge.Secrets, models.SecretRequest{SecretName: fmt.Sprintf("%03d-%s", i, strings.Repeat("n", 36))})
	}

	c, calls := recordingAPI(t)
	if err := c.UpdateWindowReport(77, testReport(1, huge)); !errors.Is(err, ErrReportTooLong) {
		t.Errorf("UpdateWindowReport = %v, want ErrReportTooLong", err)
	}
	if _, err := c.SendWindowReport(testReport(1, huge)); !errors.Is(err, ErrReportTooLong) {
		t.Errorf("SendWindowReport = %v, want ErrReportTooLong", err)
	}
	if len(*calls) != 0 {
		t.Errorf("sent %d calls to Telegram, want none", len(*calls))
	}
}

func TestWindowReport_ReleaseWithoutAVault_DoesNotShowThePlaceholder(t *testing.T) {
	c, calls := recordingAPI(t)
	anyVault := release("queue", "10.0.0.7", "deploy")
	anyVault.Vault = "_auto_"

	c.UpdateWindowReport(77, testReport(1, anyVault))

	text := (*calls)[0].Body["text"].(string)
	if !strings.Contains(text, "<code>queue</code> — ") || strings.Contains(text, "_auto_") {
		t.Errorf("a release without a vault does not show just its name:\n%s", text)
	}
}

func TestWindowReport_ComparesAndShowsOnlyTheHostOfAnIP(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(3,
		release("db", "10.0.0.9:40001", "deploy"),
		release("db", "[2001:db8::1]:40002", "deploy"),
		release("db", "10.0.0.7:51240", "deploy"))
	report.Opened.RequesterIP = "10.0.0.7:51234"

	c.UpdateWindowReport(77, report)

	text := (*calls)[0].Body["text"].(string)
	for _, want := range []string{"from <code>10.0.0.9</code>", "from <code>2001:db8::1</code>"} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not show %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "10.0.0.7") {
		t.Errorf("a release from the window's own host on another port shows its IP:\n%s", text)
	}
}

func TestWindowReport_LongForwardedFor_IsCut(t *testing.T) {
	c, calls := recordingAPI(t)

	c.UpdateWindowReport(77, testReport(1, release("db", strings.Repeat("9", 500), "deploy")))

	text := (*calls)[0].Body["text"].(string)
	if !strings.Contains(text, strings.Repeat("9", 64)+"…") || strings.Contains(text, strings.Repeat("9", 65)) {
		t.Errorf("a release does not show exactly 64 characters of a long IP:\n%s", text)
	}
}

func TestWindowReport_NamesTheVaultOfEachReleasedSecret(t *testing.T) {
	c, calls := recordingAPI(t)
	single := release("db", "10.0.0.7", "deploy")
	single.Vault = "Prod"
	batch := release("", "10.0.0.7", "deploy")
	batch.Secrets = []models.SecretRequest{{SecretName: "api", Vault: "Dev"}, {SecretName: "cache"}}
	anyVault := release("queue", "10.0.0.7", "deploy")
	anyVault.Vault = ""

	c.UpdateWindowReport(77, testReport(3, single, batch, anyVault))

	text := (*calls)[0].Body["text"].(string)
	for _, want := range []string{
		"<code>db</code> in <code>Prod</code> — ",
		"<code>api</code> in <code>Dev</code>, <code>cache</code> — ",
		"<code>queue</code> — ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not show %q:\n%s", want, text)
		}
	}
}

// replyingAPI answers every Bot API call with status and body.
func replyingAPI(t *testing.T, status int, body string) *Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	c := New(testToken, 42)
	c.baseURL = srv.URL + "/bot" + testToken
	return c
}

func TestUpdateWindowReport_OfAMessageThatIsGone_SaysSo(t *testing.T) {
	for _, description := range []string{"Bad Request: message to edit not found", "Bad Request: message can't be edited"} {
		c := replyingAPI(t, http.StatusBadRequest, fmt.Sprintf(`{"ok":false,"error_code":400,"description":%q}`, description))

		err := c.UpdateWindowReport(77, testReport(1, release("db", "10.0.0.7", "deploy")))

		if !errors.Is(err, ErrMessageGone) {
			t.Errorf("%q: error = %v, want ErrMessageGone", description, err)
		}
	}
}

func TestUpdateWindowReport_WhenTelegramIsBusyOrDown_DoesNotSayTheMessageIsGone(t *testing.T) {
	replies := map[int]string{
		http.StatusTooManyRequests: `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 5","parameters":{"retry_after":5}}`,
		http.StatusBadGateway:      `<html>Bad Gateway</html>`,
		http.StatusBadRequest:      `{"ok":false,"error_code":400,"description":"Bad Request: message is too long"}`,
	}
	for status, body := range replies {
		c := replyingAPI(t, status, body)

		err := c.UpdateWindowReport(77, testReport(1, release("db", "10.0.0.7", "deploy")))

		if err == nil || errors.Is(err, ErrMessageGone) {
			t.Errorf("%d: error = %v, want an error that does not say the message is gone", status, err)
		}
	}
}

func TestUpdateWindowReport_ThatChangesNothing_Succeeds(t *testing.T) {
	c := replyingAPI(t, http.StatusBadRequest, `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message"}`)

	if err := c.UpdateWindowReport(77, testReport(1, release("db", "10.0.0.7", "deploy"))); err != nil {
		t.Errorf("UpdateWindowReport = %v, want success: the message already shows the report", err)
	}
}

func TestWindowReport_ShowsAnIPOnlyWhenItDiffers(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(2, release("db", "10.0.0.9", "deploy"), release("db", "10.0.0.7", "deploy"))

	c.UpdateWindowReport(77, report)

	text := (*calls)[0].Body["text"].(string)
	if !strings.Contains(text, "10.0.0.9") {
		t.Errorf("a release from another IP does not show it:\n%s", text)
	}
	if strings.Contains(text, "10.0.0.7") {
		t.Errorf("a release from the window's own IP shows it:\n%s", text)
	}
}

func TestSendSessionEnded_NamesTheMachine(t *testing.T) {
	c, calls := recordingAPI(t)

	if err := c.SendSessionEnded("devvm", "franz", 0); err != nil {
		t.Fatalf("SendSessionEnded: %v", err)
	}

	call := (*calls)[0]
	if call.Method != "sendMessage" || !strings.Contains(call.Body["text"].(string), "devvm") {
		t.Errorf("sent %s %v, want a message naming devvm", call.Method, call.Body["text"])
	}
}

func TestSendSessionEnded_SaysWhetherOtherWindowsStayOpen(t *testing.T) {
	cases := map[int]string{
		0: "The next request from this machine asks for approval again.",
		1: "1 other approval window of this machine stays open. The End button of any of them closes them all.",
		2: "2 other approval windows of this machine stay open. The End button of any of them closes them all.",
	}
	for stillOpen, want := range cases {
		c, calls := recordingAPI(t)

		if err := c.SendSessionEnded("devvm", "the gate", stillOpen); err != nil {
			t.Fatalf("SendSessionEnded: %v", err)
		}

		text := (*calls)[0].Body["text"].(string)
		if !strings.HasSuffix(text, want) {
			t.Errorf("with %d windows still open the message ends:\n%s\nwant it to end with %q", stillOpen, text, want)
		}
	}
}

func TestSendSessionEnded_SaysWhoEndedIt(t *testing.T) {
	for _, by := range []string{"@franz", "the gate: the secret could not be fetched"} {
		c, calls := recordingAPI(t)

		if err := c.SendSessionEnded("devvm", by, 0); err != nil {
			t.Fatalf("SendSessionEnded: %v", err)
		}

		text := (*calls)[0].Body["text"].(string)
		if !strings.Contains(text, "<b>Ended by:</b> "+by+"\n") {
			t.Errorf("message does not say the window was ended by %q:\n%s", by, text)
		}
	}
}

func TestButtonData_FitsTelegramsLimit(t *testing.T) {
	c, calls := recordingAPI(t)
	req := testRequest()
	req.SessionTTL = 8 * time.Hour
	req.SessionID = "fedcba9876543210fedcba9876543210"
	req.SessionExpiresAt = time.Now().Add(8 * time.Hour)

	c.SendApprovalRequest(req, "")
	c.SendWindowReport(testReport(0))

	// Telegram rejects callback_data longer than 64 bytes.
	for _, call := range *calls {
		for _, data := range buttonData(t, call) {
			if len(data) > 64 {
				t.Errorf("callback data %q is %d bytes, limit is 64", data, len(data))
			}
		}
	}
}

func TestWindowLabel(t *testing.T) {
	cases := map[time.Duration]string{
		8 * time.Hour:    "8h",
		30 * time.Minute: "30m",
		90 * time.Minute: "1h30m",
		45 * time.Second: "45s",
	}
	for ttl, want := range cases {
		if got := windowLabel(ttl); got != want {
			t.Errorf("windowLabel(%s) = %q, want %q", ttl, got, want)
		}
	}
}
