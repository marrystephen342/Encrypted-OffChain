
;; title: Encrypted-OffChain


(define-non-fungible-token vault-access uint)

(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-token-owner (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-not-found (err u103))
(define-constant err-unauthorized (err u104))
(define-constant err-invalid-input (err u105))

(define-data-var last-vault-id uint u0)

(define-map vault-metadata
  { vault-id: uint }
  {
    owner: principal,
    name: (string-ascii 50),
    created-at: uint,
    last-updated: uint
  }
)

(define-map vault-encryption-details
  { vault-id: uint }
  {
    public-key: (string-ascii 255),
    encryption-version: (string-ascii 20)
  }
)

(define-map vault-entries
  { vault-id: uint, entry-id: uint }
  {
    encrypted-data: (string-ascii 1024),
    metadata: (string-ascii 255),
    last-updated: uint
  }
)

(define-map user-vault-entries
  { user: principal }
  { entry-count: uint }
)

(define-map vault-entry-count
  { vault-id: uint }
  { count: uint }
)

(define-read-only (get-last-vault-id)
  (var-get last-vault-id)
)

(define-read-only (get-vault-metadata (vault-id uint))
  (map-get? vault-metadata { vault-id: vault-id })
)

(define-read-only (get-vault-encryption-details (vault-id uint))
  (map-get? vault-encryption-details { vault-id: vault-id })
)

(define-read-only (get-vault-entry (vault-id uint) (entry-id uint))
  (map-get? vault-entries { vault-id: vault-id, entry-id: entry-id })
)

(define-read-only (get-vault-entry-count (vault-id uint))
  (default-to { count: u0 } (map-get? vault-entry-count { vault-id: vault-id }))
)

(define-read-only (get-user-vaults (user principal))
  (let ((entry-count (default-to { entry-count: u0 } (map-get? user-vault-entries { user: user }))))
    entry-count
  )
)

(define-read-only (is-vault-owner (vault-id uint) (user principal))
  (let ((vault-data (map-get? vault-metadata { vault-id: vault-id })))
    (if (is-some vault-data)
      (is-eq (get owner (unwrap-panic vault-data)) user)
      false
    )
  )
)

(define-read-only (owns-token (vault-id uint) (user principal))
  (is-eq (some user) (nft-get-owner? vault-access vault-id))
)

(define-public (create-vault (name (string-ascii 50)) (public-key (string-ascii 255)) (encryption-version (string-ascii 20)))
  (let
    (
      (new-vault-id (+ (var-get last-vault-id) u1))
      (user tx-sender)
    )
    (asserts! (is-some (map-get? user-vault-entries { user: user })) err-unauthorized)
    (try! (nft-mint? vault-access new-vault-id user))
    (map-set vault-metadata
      { vault-id: new-vault-id }
      {
        owner: user,
        name: name,
        created-at: stacks-block-height,
        last-updated: stacks-block-height
      }
    )
    (map-set vault-encryption-details
      { vault-id: new-vault-id }
      {
        public-key: public-key,
        encryption-version: encryption-version
      }
    )
    (map-set vault-entry-count
      { vault-id: new-vault-id }
      { count: u0 }
    )
    (var-set last-vault-id new-vault-id)
    (ok new-vault-id)
  )
)

(define-public (register-user)
  (let ((user tx-sender))
    (if (is-some (map-get? user-vault-entries { user: user }))
      (err err-already-exists)
      (begin
        (map-set user-vault-entries
          { user: user }
          { entry-count: u0 }
        )
        (ok true)
      )
    )
  )
)

(define-public (add-vault-entry (vault-id uint) (encrypted-data (string-ascii 1024)) (metadata (string-ascii 255)))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
      (entry-count-data (get-vault-entry-count vault-id))
      (new-entry-id (+ (get count entry-count-data) u1))
    )
    (asserts! (is-some vault-data) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-set vault-entries
      { vault-id: vault-id, entry-id: new-entry-id }
      {
        encrypted-data: encrypted-data,
        metadata: metadata,
        last-updated: stacks-block-height
      }
    )
    
    (map-set vault-entry-count
      { vault-id: vault-id }
      { count: new-entry-id }
    )
    
    (ok new-entry-id)
  )
)

(define-public (update-vault-entry (vault-id uint) (entry-id uint) (encrypted-data (string-ascii 1024)) (metadata (string-ascii 255)))
  (let
    (
      (user tx-sender)
      (entry (map-get? vault-entries { vault-id: vault-id, entry-id: entry-id }))
    )
    (asserts! (is-some entry) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-set vault-entries
      { vault-id: vault-id, entry-id: entry-id }
      {
        encrypted-data: encrypted-data,
        metadata: metadata,
        last-updated: stacks-block-height
      }
    )
    
    (ok true)
  )
)

(define-public (delete-vault-entry (vault-id uint) (entry-id uint))
  (let
    (
      (user tx-sender)
      (entry (map-get? vault-entries { vault-id: vault-id, entry-id: entry-id }))
    )
    (asserts! (is-some entry) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-delete vault-entries { vault-id: vault-id, entry-id: entry-id })
    
    (ok true)
  )
)

(define-public (update-encryption-details (vault-id uint) (public-key (string-ascii 255)) (encryption-version (string-ascii 20)))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
    )
    (asserts! (is-some vault-data) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-set vault-encryption-details
      { vault-id: vault-id }
      {
        public-key: public-key,
        encryption-version: encryption-version
      }
    )
    
    (map-set vault-metadata
      { vault-id: vault-id }
      (merge (unwrap-panic vault-data) { last-updated: stacks-block-height })
    )
    
    (ok true)
  )
)

(define-public (transfer-vault (vault-id uint) (recipient principal))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
    )
    (asserts! (is-some vault-data) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (try! (nft-transfer? vault-access vault-id user recipient))
    
    (map-set vault-metadata
      { vault-id: vault-id }
      (merge (unwrap-panic vault-data) { owner: recipient, last-updated: stacks-block-height })
    )
    
    (ok true)
  )
)



(define-map vault-access-control
  { vault-id: uint, accessor: principal }
  { 
    can-read: bool,
    granted-at: uint,
    granted-by: principal
  }
)

(define-public (grant-vault-access (vault-id uint) (accessor principal))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
    )
    (asserts! (is-some vault-data) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-set vault-access-control
      { vault-id: vault-id, accessor: accessor }
      {
        can-read: true,
        granted-at: stacks-block-height,
        granted-by: user
      }
    )
    (ok true)
  )
)

(define-public (revoke-vault-access (vault-id uint) (accessor principal))
  (let
    (
      (user tx-sender)
    )
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    (map-delete vault-access-control { vault-id: vault-id, accessor: accessor })
    (ok true)
  )
)

(define-read-only (can-access-vault (vault-id uint) (accessor principal))
  (let ((access-data (map-get? vault-access-control { vault-id: vault-id, accessor: accessor })))
    (if (is-some access-data)
      (get can-read (unwrap-panic access-data))
      false
    )
  )
)



(define-map entry-tags
  { vault-id: uint, entry-id: uint, tag: (string-ascii 20) }
  { created-at: uint }
)

(define-map entry-tag-count
  { vault-id: uint, entry-id: uint }
  { count: uint }
)

(define-public (add-entry-tag (vault-id uint) (entry-id uint) (tag (string-ascii 20)))
  (let
    (
      (user tx-sender)
      (entry (map-get? vault-entries { vault-id: vault-id, entry-id: entry-id }))
      (current-count (default-to { count: u0 } 
        (map-get? entry-tag-count { vault-id: vault-id, entry-id: entry-id })))
    )
    (asserts! (is-some entry) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-set entry-tags
      { vault-id: vault-id, entry-id: entry-id, tag: tag }
      { created-at: stacks-block-height }
    )
    
    (map-set entry-tag-count
      { vault-id: vault-id, entry-id: entry-id }
      { count: (+ (get count current-count) u1) }
    )
    
    (ok true)
  )
)

(define-public (remove-entry-tag (vault-id uint) (entry-id uint) (tag (string-ascii 20)))
  (let
    (
      (user tx-sender)
      (current-count (default-to { count: u0 } 
        (map-get? entry-tag-count { vault-id: vault-id, entry-id: entry-id })))
    )
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    (map-delete entry-tags { vault-id: vault-id, entry-id: entry-id, tag: tag })
    
    (map-set entry-tag-count
      { vault-id: vault-id, entry-id: entry-id }
      { count: (- (get count current-count) u1) }
    )
    
    (ok true)
  )
)

(define-read-only (has-tag (vault-id uint) (entry-id uint) (tag (string-ascii 20)))
  (is-some (map-get? entry-tags { vault-id: vault-id, entry-id: entry-id, tag: tag }))
)


(define-map vault-time-limited-access
  { vault-id: uint, accessor: principal }
  {
    expires-at: uint,
    granted-at: uint,
    granted-by: principal,
    access-fee: uint
  }
)

(define-map pending-access-payments
  { vault-id: uint, accessor: principal }
  { amount: uint }
)

(define-data-var platform-fee-rate uint u250)

(define-public (grant-time-limited-access (vault-id uint) (accessor principal) (duration-blocks uint) (access-fee uint))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
      (expires-at (+ stacks-block-height duration-blocks))
    )
    (asserts! (is-some vault-data) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    (asserts! (> duration-blocks u0) err-invalid-input)
    
    (map-set vault-time-limited-access
      { vault-id: vault-id, accessor: accessor }
      {
        expires-at: expires-at,
        granted-at: stacks-block-height,
        granted-by: user,
        access-fee: access-fee
      }
    )
    
    (if (> access-fee u0)
      (map-set pending-access-payments
        { vault-id: vault-id, accessor: accessor }
        { amount: access-fee }
      )
      true
    )
    
    (ok expires-at)
  )
)

(define-public (pay-for-vault-access (vault-id uint))
  (let
    (
      (user tx-sender)
      (payment-data (map-get? pending-access-payments { vault-id: vault-id, accessor: user }))
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
      (access-data (map-get? vault-time-limited-access { vault-id: vault-id, accessor: user }))
    )
    (asserts! (is-some payment-data) err-not-found)
    (asserts! (is-some vault-data) err-not-found)
    (asserts! (is-some access-data) err-not-found)
    
    (let
      (
        (payment-amount (get amount (unwrap-panic payment-data)))
        (vault-owner (get owner (unwrap-panic vault-data)))
        (platform-fee (/ (* payment-amount (var-get platform-fee-rate)) u10000))
        (owner-payment (- payment-amount platform-fee))
      )
      (try! (stx-transfer? owner-payment user vault-owner))
      (try! (stx-transfer? platform-fee user contract-owner))
      
      (map-delete pending-access-payments { vault-id: vault-id, accessor: user })
      (ok true)
    )
  )
)

(define-public (revoke-time-limited-access (vault-id uint) (accessor principal))
  (let
    (
      (user tx-sender)
    )
    (asserts! (owns-token vault-id user) err-not-token-owner)
    (map-delete vault-time-limited-access { vault-id: vault-id, accessor: accessor })
    (map-delete pending-access-payments { vault-id: vault-id, accessor: accessor })
    (ok true)
  )
)

(define-read-only (can-access-vault-time-limited (vault-id uint) (accessor principal))
  (let 
    (
      (access-data (map-get? vault-time-limited-access { vault-id: vault-id, accessor: accessor }))
      (payment-pending (is-some (map-get? pending-access-payments { vault-id: vault-id, accessor: accessor })))
    )
    (if (is-some access-data)
      (let ((access-info (unwrap-panic access-data)))
        (and 
          (< stacks-block-height (get expires-at access-info))
          (not payment-pending)
        )
      )
      false
    )
  )
)

(define-read-only (get-time-limited-access-info (vault-id uint) (accessor principal))
  (map-get? vault-time-limited-access { vault-id: vault-id, accessor: accessor })
)

(define-read-only (get-pending-payment (vault-id uint) (accessor principal))
  (map-get? pending-access-payments { vault-id: vault-id, accessor: accessor })
)

(define-read-only (has-valid-access (vault-id uint) (accessor principal))
  (or 
    (can-access-vault vault-id accessor)
    (can-access-vault-time-limited vault-id accessor)
    (owns-token vault-id accessor)
  )
)

(define-public (cleanup-expired-access (vault-id uint) (accessor principal))
  (let
    (
      (access-data (map-get? vault-time-limited-access { vault-id: vault-id, accessor: accessor }))
    )
    (asserts! (is-some access-data) err-not-found)
    (asserts! (>= stacks-block-height (get expires-at (unwrap-panic access-data))) err-unauthorized)
    
    (map-delete vault-time-limited-access { vault-id: vault-id, accessor: accessor })
    (map-delete pending-access-payments { vault-id: vault-id, accessor: accessor })
    (ok true)
  )
)

(define-public (set-platform-fee-rate (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (<= new-rate u1000) err-invalid-input)
    (var-set platform-fee-rate new-rate)
    (ok true)
  )
)

(define-read-only (get-platform-fee-rate)
  (var-get platform-fee-rate)
)

(define-data-var last-snapshot-id uint u0)

(define-map vault-snapshots
  { vault-id: uint, snapshot-id: uint }
  {
    name: (string-ascii 50),
    created-at: uint,
    entry-count: uint,
    creator: principal
  }
)

(define-map snapshot-entries
  { vault-id: uint, snapshot-id: uint, entry-id: uint }
  {
    encrypted-data: (string-ascii 1024),
    metadata: (string-ascii 255),
    tags: (list 10 (string-ascii 20))
  }
)

(define-map vault-snapshot-count
  { vault-id: uint }
  { count: uint }
)

(define-read-only (get-vault-snapshot-count (vault-id uint))
  (default-to { count: u0 } (map-get? vault-snapshot-count { vault-id: vault-id }))
)

(define-read-only (get-snapshot-info (vault-id uint) (snapshot-id uint))
  (map-get? vault-snapshots { vault-id: vault-id, snapshot-id: snapshot-id })
)

(define-read-only (get-snapshot-entry (vault-id uint) (snapshot-id uint) (entry-id uint))
  (map-get? snapshot-entries { vault-id: vault-id, snapshot-id: snapshot-id, entry-id: entry-id })
)

(define-private (collect-entry-tags (entry-id uint) (vault-id uint) (tags (list 10 (string-ascii 20))))
  (let
    (
      (tag-1 "crypto")
      (tag-2 "personal")
      (tag-3 "work")
      (tag-4 "backup")
      (tag-5 "temp")
    )
    (list tag-1 tag-2 tag-3 tag-4 tag-5)
  )
)

(define-public (create-vault-snapshot (vault-id uint) (snapshot-name (string-ascii 50)))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
      (entry-count-data (get-vault-entry-count vault-id))
      (snapshot-count-data (get-vault-snapshot-count vault-id))
      (new-snapshot-id (+ (var-get last-snapshot-id) u1))
      (new-vault-snapshot-count (+ (get count snapshot-count-data) u1))
    )
    (asserts! (is-some vault-data) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (map-set vault-snapshots
      { vault-id: vault-id, snapshot-id: new-snapshot-id }
      {
        name: snapshot-name,
        created-at: stacks-block-height,
        entry-count: (get count entry-count-data),
        creator: user
      }
    )
    
    (map-set vault-snapshot-count
      { vault-id: vault-id }
      { count: new-vault-snapshot-count }
    )
    
    (var-set last-snapshot-id new-snapshot-id)
    (ok new-snapshot-id)
  )
)

(define-public (snapshot-vault-entry (vault-id uint) (snapshot-id uint) (entry-id uint))
  (let
    (
      (user tx-sender)
      (entry-data (map-get? vault-entries { vault-id: vault-id, entry-id: entry-id }))
      (snapshot-info (map-get? vault-snapshots { vault-id: vault-id, snapshot-id: snapshot-id }))
    )
    (asserts! (is-some entry-data) err-not-found)
    (asserts! (is-some snapshot-info) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (let ((entry (unwrap-panic entry-data)))
      (map-set snapshot-entries
        { vault-id: vault-id, snapshot-id: snapshot-id, entry-id: entry-id }
        {
          encrypted-data: (get encrypted-data entry),
          metadata: (get metadata entry),
          tags: (collect-entry-tags entry-id vault-id (list))
        }
      )
    )
    (ok true)
  )
)

(define-public (restore-from-snapshot (vault-id uint) (snapshot-id uint) (entry-id uint))
  (let
    (
      (user tx-sender)
      (snapshot-entry (map-get? snapshot-entries { vault-id: vault-id, snapshot-id: snapshot-id, entry-id: entry-id }))
      (snapshot-info (map-get? vault-snapshots { vault-id: vault-id, snapshot-id: snapshot-id }))
    )
    (asserts! (is-some snapshot-entry) err-not-found)
    (asserts! (is-some snapshot-info) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (let ((entry (unwrap-panic snapshot-entry)))
      (map-set vault-entries
        { vault-id: vault-id, entry-id: entry-id }
        {
          encrypted-data: (get encrypted-data entry),
          metadata: (get metadata entry),
          last-updated: stacks-block-height
        }
      )
    )
    (ok true)
  )
)

(define-public (delete-vault-snapshot (vault-id uint) (snapshot-id uint))
  (let
    (
      (user tx-sender)
      (snapshot-info (map-get? vault-snapshots { vault-id: vault-id, snapshot-id: snapshot-id }))
    )
    (asserts! (is-some snapshot-info) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (map-delete vault-snapshots { vault-id: vault-id, snapshot-id: snapshot-id })
    (ok true)
  )
)

;; Vault Inheritance Protocol
(define-data-var inheritance-claim-period uint u144000) ;; ~100 days in blocks

(define-map vault-inheritance-rules
  { vault-id: uint }
  {
    beneficiary: principal,
    backup-beneficiary: principal,
    inheritance-delay: uint,
    requires-verification: bool,
    created-at: uint,
    last-owner-activity: uint
  }
)

(define-map inheritance-claims
  { vault-id: uint, claimant: principal }
  {
    claim-initiated-at: uint,
    verification-deadline: uint,
    claim-status: (string-ascii 20),
    required-confirmations: uint,
    current-confirmations: uint
  }
)

(define-map inheritance-verifiers
  { vault-id: uint, verifier: principal }
  {
    authorized-by: principal,
    verification-weight: uint,
    added-at: uint
  }
)

(define-map verifier-confirmations
  { vault-id: uint, verifier: principal, claimant: principal }
  {
    confirmed-at: uint,
    verification-message: (string-ascii 100)
  }
)

(define-map vault-inheritance-activity
  { vault-id: uint }
  { last-activity-block: uint }
)

;; Read-only functions for inheritance system
(define-read-only (get-inheritance-rules (vault-id uint))
  (map-get? vault-inheritance-rules { vault-id: vault-id })
)

(define-read-only (get-inheritance-claim (vault-id uint) (claimant principal))
  (map-get? inheritance-claims { vault-id: vault-id, claimant: claimant })
)

(define-read-only (get-vault-activity (vault-id uint))
  (default-to { last-activity-block: u0 } 
    (map-get? vault-inheritance-activity { vault-id: vault-id }))
)

(define-read-only (is-inheritance-eligible (vault-id uint))
  (let 
    (
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
      (activity (get-vault-activity vault-id))
    )
    (if (is-some rules)
      (let ((rule-data (unwrap-panic rules)))
        (>= (- stacks-block-height (get last-activity-block activity)) 
            (get inheritance-delay rule-data))
      )
      false
    )
  )
)

(define-read-only (can-claim-inheritance (vault-id uint) (claimant principal))
  (let ((rules (map-get? vault-inheritance-rules { vault-id: vault-id })))
    (if (is-some rules)
      (let ((rule-data (unwrap-panic rules)))
        (and 
          (or 
            (is-eq claimant (get beneficiary rule-data))
            (is-eq claimant (get backup-beneficiary rule-data))
          )
          (is-inheritance-eligible vault-id)
        )
      )
      false
    )
  )
)

;; Update vault activity tracker
(define-private (update-vault-activity (vault-id uint))
  (map-set vault-inheritance-activity
    { vault-id: vault-id }
    { last-activity-block: stacks-block-height }
  )
)

;; Setup inheritance rules for a vault
(define-public (setup-vault-inheritance 
  (vault-id uint) 
  (beneficiary principal) 
  (backup-beneficiary principal) 
  (inheritance-delay uint)
  (requires-verification bool))
  (let
    (
      (user tx-sender)
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
    )
    (asserts! (is-some vault-data) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    (asserts! (> inheritance-delay u1000) err-invalid-input) ;; Minimum ~16 hours
    (asserts! (not (is-eq beneficiary user)) err-invalid-input)
    (asserts! (not (is-eq backup-beneficiary user)) err-invalid-input)
    
    (map-set vault-inheritance-rules
      { vault-id: vault-id }
      {
        beneficiary: beneficiary,
        backup-beneficiary: backup-beneficiary,
        inheritance-delay: inheritance-delay,
        requires-verification: requires-verification,
        created-at: stacks-block-height,
        last-owner-activity: stacks-block-height
      }
    )
    
    (update-vault-activity vault-id)
    (ok true)
  )
)

;; Authorize verifiers for inheritance claims
(define-public (authorize-inheritance-verifier (vault-id uint) (verifier principal) (weight uint))
  (let
    (
      (user tx-sender)
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
    )
    (asserts! (is-some rules) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    (asserts! (and (> weight u0) (<= weight u10)) err-invalid-input)
    (asserts! (not (is-eq verifier user)) err-invalid-input)
    
    (map-set inheritance-verifiers
      { vault-id: vault-id, verifier: verifier }
      {
        authorized-by: user,
        verification-weight: weight,
        added-at: stacks-block-height
      }
    )
    
    (update-vault-activity vault-id)
    (ok true)
  )
)

;; Initiate inheritance claim
(define-public (initiate-inheritance-claim (vault-id uint))
  (let
    (
      (user tx-sender)
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
      (existing-claim (map-get? inheritance-claims { vault-id: vault-id, claimant: user }))
    )
    (asserts! (is-some rules) err-not-found)
    (asserts! (is-none existing-claim) err-already-exists)
    (asserts! (can-claim-inheritance vault-id user) err-unauthorized)
    
    (let 
      (
        (rule-data (unwrap-panic rules))
        (verification-period (var-get inheritance-claim-period))
        (required-confirmations (if (get requires-verification rule-data) u2 u0))
      )
      (map-set inheritance-claims
        { vault-id: vault-id, claimant: user }
        {
          claim-initiated-at: stacks-block-height,
          verification-deadline: (+ stacks-block-height verification-period),
          claim-status: "pending",
          required-confirmations: required-confirmations,
          current-confirmations: u0
        }
      )
    )
    
    (ok true)
  )
)

;; Verify inheritance claim by authorized verifier
(define-public (verify-inheritance-claim (vault-id uint) (claimant principal) (message (string-ascii 100)))
  (let
    (
      (user tx-sender)
      (verifier-data (map-get? inheritance-verifiers { vault-id: vault-id, verifier: user }))
      (claim (map-get? inheritance-claims { vault-id: vault-id, claimant: claimant }))
      (existing-confirmation (map-get? verifier-confirmations { vault-id: vault-id, verifier: user, claimant: claimant }))
    )
    (asserts! (is-some verifier-data) err-unauthorized)
    (asserts! (is-some claim) err-not-found)
    (asserts! (is-none existing-confirmation) err-already-exists)
    
    (let 
      (
        (claim-data (unwrap-panic claim))
        (verifier-info (unwrap-panic verifier-data))
        (new-confirmations (+ (get current-confirmations claim-data) (get verification-weight verifier-info)))
      )
      (asserts! (< stacks-block-height (get verification-deadline claim-data)) err-unauthorized)
      
      ;; Record verifier confirmation
      (map-set verifier-confirmations
        { vault-id: vault-id, verifier: user, claimant: claimant }
        {
          confirmed-at: stacks-block-height,
          verification-message: message
        }
      )
      
      ;; Update claim with new confirmation count
      (map-set inheritance-claims
        { vault-id: vault-id, claimant: claimant }
        (merge claim-data { current-confirmations: new-confirmations })
      )
    )
    
    (ok true)
  )
)

;; Execute inheritance claim and transfer vault ownership
(define-public (execute-inheritance-claim (vault-id uint))
  (let
    (
      (user tx-sender)
      (claim (map-get? inheritance-claims { vault-id: vault-id, claimant: user }))
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
      (vault-data (map-get? vault-metadata { vault-id: vault-id }))
    )
    (asserts! (is-some claim) err-not-found)
    (asserts! (is-some rules) err-not-found)
    (asserts! (is-some vault-data) err-not-found)
    
    (let 
      (
        (claim-data (unwrap-panic claim))
        (rule-data (unwrap-panic rules))
        (current-owner (get owner (unwrap-panic vault-data)))
      )
      ;; Verify claim is ready for execution
      (asserts! (>= stacks-block-height (get verification-deadline claim-data)) err-unauthorized)
      (asserts! (>= (get current-confirmations claim-data) (get required-confirmations claim-data)) err-unauthorized)
      
      ;; Transfer vault ownership
      (try! (nft-transfer? vault-access vault-id current-owner user))
      
      ;; Update vault metadata
      (map-set vault-metadata
        { vault-id: vault-id }
        (merge (unwrap-panic vault-data) { owner: user, last-updated: stacks-block-height })
      )
      
      ;; Update inheritance rules with new owner
      (map-delete vault-inheritance-rules { vault-id: vault-id })
      (map-delete inheritance-claims { vault-id: vault-id, claimant: user })
      
      (update-vault-activity vault-id)
    )
    
    (ok true)
  )
)

;; Reset inheritance claim (owner activity proof)
(define-public (reset-inheritance-timer (vault-id uint))
  (let
    (
      (user tx-sender)
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
    )
    (asserts! (is-some rules) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (update-vault-activity vault-id)
    
    ;; Cancel any pending claims
    (let ((rule-data (unwrap-panic rules)))
      (map-delete inheritance-claims { vault-id: vault-id, claimant: (get beneficiary rule-data) })
      (map-delete inheritance-claims { vault-id: vault-id, claimant: (get backup-beneficiary rule-data) })
    )
    
    (ok true)
  )
)

;; Update inheritance settings
(define-public (update-inheritance-rules (vault-id uint) (new-delay uint) (new-verification bool))
  (let
    (
      (user tx-sender)
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
    )
    (asserts! (is-some rules) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    (asserts! (> new-delay u1000) err-invalid-input)
    
    (let ((current-rules (unwrap-panic rules)))
      (map-set vault-inheritance-rules
        { vault-id: vault-id }
        (merge current-rules 
          { 
            inheritance-delay: new-delay,
            requires-verification: new-verification,
            last-owner-activity: stacks-block-height
          }
        )
      )
    )
    
    (update-vault-activity vault-id)
    (ok true)
  )
)

;; Remove inheritance rules entirely
(define-public (remove-inheritance-rules (vault-id uint))
  (let
    (
      (user tx-sender)
      (rules (map-get? vault-inheritance-rules { vault-id: vault-id }))
    )
    (asserts! (is-some rules) err-not-found)
    (asserts! (owns-token vault-id user) err-not-token-owner)
    
    (map-delete vault-inheritance-rules { vault-id: vault-id })
    (update-vault-activity vault-id)
    (ok true)
  )
)





