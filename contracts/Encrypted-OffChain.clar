
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
    (asserts! (is-some (map-get? user-vault-entries { user: user })) (err err-unauthorized))
    ;; (try! (nft-mint? vault-access new-vault-id user))
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
    (asserts! (is-some vault-data) (err err-not-found))
    (asserts! (owns-token vault-id user) (err err-not-token-owner))
    
    ;; (try! (nft-transfer? vault-access vault-id user recipient))
    
    (map-set vault-metadata
      { vault-id: vault-id }
      (merge (unwrap-panic vault-data) { owner: recipient, last-updated: stacks-block-height })
    )
    
    (ok true)
  )
)