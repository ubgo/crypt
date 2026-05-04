// Audit log with HMAC-chained integrity.
//
// Pattern: each log entry is signed with HMAC over (previous-MAC ||
// payload). The chain binds every entry to all prior entries —
// removing or modifying any entry breaks the chain. Verification
// recomputes the chain forward; if any step fails, the log has been
// tampered.
//
// Use cases: regulated audit trails (SOC2, HIPAA), security event
// logging, anything where "did this entry exist as written?" matters.
//
// Caveat: the secret must be protected. If the secret leaks, the
// attacker can rewrite the chain. For stronger guarantees, consider
// signed logs with rotating ephemeral keys + a hardware-anchored root.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/ubgo/crypt"
)

type AuditEntry struct {
	Timestamp time.Time
	Actor     string
	Action    string
	Resource  string
	MAC       []byte // HMAC over (prevMAC || payload)
}

func (e AuditEntry) payload() []byte {
	return fmt.Appendf(nil, "%s|%s|%s|%s",
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.Actor,
		e.Action,
		e.Resource,
	)
}

type AuditLog struct {
	secret  []byte
	entries []AuditEntry
}

func NewAuditLog(secret []byte) *AuditLog {
	return &AuditLog{secret: secret}
}

func (l *AuditLog) Append(actor, action, resource string) {
	prev := []byte{}
	if len(l.entries) > 0 {
		prev = l.entries[len(l.entries)-1].MAC
	}
	e := AuditEntry{
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Resource:  resource,
	}
	signed := append(append([]byte{}, prev...), e.payload()...)
	e.MAC = crypt.Sign(l.secret, signed)
	l.entries = append(l.entries, e)
}

// Verify walks the chain and reports the first index that breaks,
// or -1 if the entire chain is valid.
func (l *AuditLog) Verify() int {
	prev := []byte{}
	for i, e := range l.entries {
		signed := append(append([]byte{}, prev...), e.payload()...)
		if !crypt.Verify(l.secret, signed, e.MAC) {
			return i
		}
		prev = e.MAC
	}
	return -1
}

func main() {
	secret := []byte("audit-log-secret-32-bytes-please")
	logger := NewAuditLog(secret)

	logger.Append("usr_42", "login", "/auth")
	logger.Append("usr_42", "view", "/billing")
	logger.Append("usr_admin", "delete", "/users/usr_99")

	if bad := logger.Verify(); bad != -1 {
		log.Fatalf("chain broken at entry %d", bad)
	}
	fmt.Println("chain valid (3 entries)")

	for i, e := range logger.entries {
		fmt.Printf("  [%d] %s %s %s %s  mac=%s\n",
			i, e.Timestamp.Format(time.RFC3339), e.Actor, e.Action, e.Resource,
			hex.EncodeToString(e.MAC[:8]))
	}

	// Tamper with the middle entry's action.
	fmt.Println("\n--- attacker rewrites entry 1 ---")
	logger.entries[1].Action = "purchase"

	if bad := logger.Verify(); bad != -1 {
		fmt.Printf("chain broken at entry %d (as expected)\n", bad)
	} else {
		fmt.Println("chain still valid — should not happen")
	}
}
