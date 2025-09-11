;; Vault Audit Trail for Encrypted-OffChain
;; This contract provides comprehensive audit logging for all vault operations

;; Error constants
(define-constant ERR_UNAUTHORIZED (err u300))
(define-constant ERR_AUDIT_NOT_FOUND (err u301))
(define-constant ERR_INVALID_PARAMETERS (err u302))
(define-constant ERR_LOG_LIMIT_EXCEEDED (err u303))

;; Constants
(define-constant MAX_LOGS_PER_VAULT u10000)
(define-constant MAX_DESCRIPTION_LENGTH u200)

;; Reference to main Encrypted-OffChain contract
(define-constant VAULT_CONTRACT .Encrypted-OffChain)

;; Data variables
(define-data-var total-audit-logs uint u0)
(define-data-var audit-retention-period uint u525600) ;; ~1 year in blocks

;; Operation type constants
(define-constant OP_VAULT_CREATED "vault-created")
(define-constant OP_ENTRY_ADDED "entry-added")
(define-constant OP_ENTRY_UPDATED "entry-updated")
(define-constant OP_ENTRY_DELETED "entry-deleted")
(define-constant OP_ACCESS_GRANTED "access-granted")
(define-constant OP_ACCESS_REVOKED "access-revoked")
(define-constant OP_VAULT_TRANSFERRED "vault-transferred")
(define-constant OP_SNAPSHOT_CREATED "snapshot-created")
(define-constant OP_INHERITANCE_SETUP "inheritance-setup")
(define-constant OP_INHERITANCE_CLAIMED "inheritance-claimed")
(define-constant OP_SUSPICIOUS_ACCESS "suspicious-access")

;; Data maps
(define-map audit-logs uint
  {
    vault-id: uint,
    operation-type: (string-ascii 20),
    performer: principal,
    target-principal: (optional principal),
    timestamp: uint,
    description: (string-ascii 200),
    entry-id: (optional uint),
    metadata: (string-ascii 100),
    risk-level: uint
  }
)

(define-map vault-audit-stats uint
  {
    total-operations: uint,
    last-activity: uint,
    high-risk-events: uint,
    unique-accessors: uint
  }
)

(define-map user-audit-summary principal
  {
    total-operations: uint,
    vaults-accessed: uint,
    high-risk-operations: uint,
    last-activity: uint
  }
)

(define-map daily-audit-summary {date: uint}
  {
    total-operations: uint,
    unique-vaults: uint,
    unique-users: uint,
    suspicious-activities: uint
  }
)

(define-map suspicious-activity-alerts uint
  {
    vault-id: uint,
    alert-type: (string-ascii 30),
    triggered-by: principal,
    timestamp: uint,
    severity: uint,
    description: (string-ascii 150),
    resolved: bool
  }
)

;; Private helper functions
(define-private (is-vault-owner (vault-id uint) (user principal))
  (let ((vault-metadata (contract-call? VAULT_CONTRACT get-vault-metadata vault-id)))
    (if (is-some vault-metadata)
      (is-eq (get owner (unwrap-panic vault-metadata)) user)
      false)
  )
)

(define-private (calculate-risk-level (operation-type (string-ascii 20)) (user principal))
  (if (or (is-eq operation-type OP_VAULT_TRANSFERRED)
          (is-eq operation-type OP_INHERITANCE_CLAIMED)
          (is-eq operation-type OP_SUSPICIOUS_ACCESS))
    u3 ;; High risk
    (if (or (is-eq operation-type OP_ACCESS_GRANTED)
            (is-eq operation-type OP_ENTRY_DELETED))
      u2 ;; Medium risk
      u1)) ;; Low risk
)

(define-private (get-day-from-block (height uint))
  ;; Simplified day calculation (144 blocks per day)
  (/ height u144)
)

(define-private (update-vault-stats (vault-id uint) (risk-level uint))
  (let ((current-stats (default-to {total-operations: u0, last-activity: u0, high-risk-events: u0, unique-accessors: u0}
                                  (map-get? vault-audit-stats vault-id))))
    (map-set vault-audit-stats vault-id
      (merge current-stats
             {total-operations: (+ (get total-operations current-stats) u1),
              last-activity: stacks-block-height,
              high-risk-events: (+ (get high-risk-events current-stats) (if (>= risk-level u3) u1 u0))}))
  )
)

(define-private (update-user-stats (user principal) (risk-level uint))
  (let ((current-stats (default-to {total-operations: u0, vaults-accessed: u0, high-risk-operations: u0, last-activity: u0}
                                  (map-get? user-audit-summary user))))
    (map-set user-audit-summary user
      (merge current-stats
             {total-operations: (+ (get total-operations current-stats) u1),
              high-risk-operations: (+ (get high-risk-operations current-stats) (if (>= risk-level u3) u1 u0)),
              last-activity: stacks-block-height}))
  )
)

(define-private (update-daily-stats)
  (let ((day (get-day-from-block stacks-block-height))
        (current-stats (default-to {total-operations: u0, unique-vaults: u0, unique-users: u0, suspicious-activities: u0}
                                  (map-get? daily-audit-summary {date: day}))))
    (map-set daily-audit-summary {date: day}
      (merge current-stats
             {total-operations: (+ (get total-operations current-stats) u1)}))
  )
)

;; Public functions

;; Log vault operation (called by vault contract or authorized users)
(define-public (log-vault-operation 
  (vault-id uint)
  (operation-type (string-ascii 20))
  (target-principal (optional principal))
  (description (string-ascii 200))
  (entry-id (optional uint))
  (metadata (string-ascii 100)))
  (let ((log-id (+ (var-get total-audit-logs) u1))
        (risk-level (calculate-risk-level operation-type tx-sender)))
    ;; Basic validation
    (asserts! (and (> vault-id u0) (> (len description) u0)) ERR_INVALID_PARAMETERS)
    
    ;; Create audit log entry
    (map-set audit-logs log-id
      {
        vault-id: vault-id,
        operation-type: operation-type,
        performer: tx-sender,
        target-principal: target-principal,
        timestamp: stacks-block-height,
        description: description,
        entry-id: entry-id,
        metadata: metadata,
        risk-level: risk-level
      }
    )
    
    ;; Update statistics
    (update-vault-stats vault-id risk-level)
    (update-user-stats tx-sender risk-level)
    (update-daily-stats)
    
    ;; Check for suspicious activity patterns
    (if (>= risk-level u3)
      (begin
        (unwrap-panic (create-suspicious-activity-alert vault-id "high-risk-operation" risk-level "High risk operation detected"))
        true)
      true
    )
    
    (var-set total-audit-logs log-id)
    (ok log-id)
  )
)

;; Create suspicious activity alert
(define-public (create-suspicious-activity-alert 
  (vault-id uint)
  (alert-type (string-ascii 30))
  (severity uint)
  (description (string-ascii 150)))
  (let ((alert-id (+ (var-get total-audit-logs) u1000))) ;; Offset alert IDs
    (map-set suspicious-activity-alerts alert-id
      {
        vault-id: vault-id,
        alert-type: alert-type,
        triggered-by: tx-sender,
        timestamp: stacks-block-height,
        severity: severity,
        description: description,
        resolved: false
      }
    )
    (ok alert-id)
  )
)

;; Resolve suspicious activity alert (vault owner only)
(define-public (resolve-suspicious-alert (alert-id uint))
  (let ((alert-data (map-get? suspicious-activity-alerts alert-id)))
    (asserts! (is-some alert-data) ERR_AUDIT_NOT_FOUND)
    (let ((alert (unwrap-panic alert-data)))
      (asserts! (is-vault-owner (get vault-id alert) tx-sender) ERR_UNAUTHORIZED)
      (map-set suspicious-activity-alerts alert-id
        (merge alert {resolved: true}))
      (ok true)
    )
  )
)

;; Read-only functions

;; Get specific audit log
(define-read-only (get-audit-log (log-id uint))
  (map-get? audit-logs log-id)
)

;; Get vault audit statistics
(define-read-only (get-vault-audit-stats (vault-id uint))
  (map-get? vault-audit-stats vault-id)
)

;; Get user audit summary
(define-read-only (get-user-audit-summary (user principal))
  (map-get? user-audit-summary user)
)

;; Get daily audit summary
(define-read-only (get-daily-audit-summary (date uint))
  (map-get? daily-audit-summary {date: date})
)

;; Get suspicious activity alert
(define-read-only (get-suspicious-alert (alert-id uint))
  (map-get? suspicious-activity-alerts alert-id)
)

;; Get recent audit logs for a vault (returns log count)
(define-read-only (get-recent-vault-activity (vault-id uint))
  (let ((stats (get-vault-audit-stats vault-id)))
    (if (is-some stats)
      (get total-operations (unwrap-panic stats))
      u0)
  )
)

;; Check if vault has high-risk activity
(define-read-only (has-high-risk-activity (vault-id uint))
  (let ((stats (map-get? vault-audit-stats vault-id)))
    (if (is-some stats)
      (> (get high-risk-events (unwrap-panic stats)) u0)
      false)
  )
)

;; Get audit summary for compliance reporting
(define-read-only (get-compliance-summary (vault-id uint))
  (let ((stats (get-vault-audit-stats vault-id)))
    (if (is-some stats)
      (let ((vault-stats (unwrap-panic stats)))
        (some {
          vault-id: vault-id,
          total-operations: (get total-operations vault-stats),
          last-activity: (get last-activity vault-stats),
          high-risk-events: (get high-risk-events vault-stats),
          risk-score: (if (> (get total-operations vault-stats) u0)
                       (/ (* (get high-risk-events vault-stats) u100) (get total-operations vault-stats))
                       u0),
          compliance-status: (if (< (get high-risk-events vault-stats) u3) "compliant" "needs-review")
        }))
      none)
  )
)

;; Get user activity pattern analysis
(define-read-only (get-user-activity-pattern (user principal))
  (let ((summary (get-user-audit-summary user)))
    (if (is-some summary)
      (let ((user-stats (unwrap-panic summary)))
        (some {
          user: user,
          activity-level: (if (> (get total-operations user-stats) u50) "high"
                           (if (> (get total-operations user-stats) u10) "medium" "low")),
          risk-ratio: (if (> (get total-operations user-stats) u0)
                       (/ (* (get high-risk-operations user-stats) u100) (get total-operations user-stats))
                       u0),
          last-seen: (get last-activity user-stats),
          needs-monitoring: (> (get high-risk-operations user-stats) u5)
        }))
      none)
  )
)

;; Check for unusual access patterns
(define-read-only (detect-unusual-patterns (vault-id uint))
  (let ((stats (get-vault-audit-stats vault-id))
        (current-day (get-day-from-block stacks-block-height)))
    (if (is-some stats)
      (let ((vault-stats (unwrap-panic stats))
            (today-stats (get-daily-audit-summary current-day)))
        {
          vault-id: vault-id,
          unusual-activity: (> (get high-risk-events vault-stats) u10),
          recent-activity-spike: (if (is-some today-stats)
                                  (> (get total-operations (unwrap-panic today-stats)) u100)
                                  false),
          requires-attention: (or (> (get high-risk-events vault-stats) u10)
                                 (> (- stacks-block-height (get last-activity vault-stats)) u1440))
        })
      {
        vault-id: vault-id,
        unusual-activity: false,
        recent-activity-spike: false,
        requires-attention: false
      })
  )
)

;; Get system-wide audit statistics
(define-read-only (get-system-audit-stats)
  (let ((current-day (get-day-from-block stacks-block-height))
        (today-stats (get-daily-audit-summary current-day)))
    {
      total-audit-logs: (var-get total-audit-logs),
      retention-period: (var-get audit-retention-period),
      todays-operations: (if (is-some today-stats)
                          (get total-operations (unwrap-panic today-stats))
                          u0),
      system-health: (if (< (var-get total-audit-logs) u50000) "healthy" "high-usage")
    }
  )
)

;; Get full audit report (basic version)
(define-read-only (get-vault-audit-report (vault-id uint))
  (some {
    vault-stats: (get-vault-audit-stats vault-id),
    compliance-summary: (get-compliance-summary vault-id),
    pattern-analysis: (detect-unusual-patterns vault-id),
    recent-activity: (get-recent-vault-activity vault-id)
  })
)

;; Check if operation should be flagged as suspicious
(define-read-only (should-flag-operation (vault-id uint) (operation-type (string-ascii 20)) (user principal))
  (let ((user-stats (get-user-audit-summary user))
        (vault-stats (get-vault-audit-stats vault-id)))
    (or
      ;; High risk operation types
      (>= (calculate-risk-level operation-type user) u3)
      ;; User with many high-risk operations
      (if (is-some user-stats)
        (> (get high-risk-operations (unwrap-panic user-stats)) u10)
        false)
      ;; Vault with too many operations in short period
      (if (is-some vault-stats)
        (and (> (get total-operations (unwrap-panic vault-stats)) u100)
             (< (- stacks-block-height (get last-activity (unwrap-panic vault-stats))) u144))
        false)
    )
  )
)
