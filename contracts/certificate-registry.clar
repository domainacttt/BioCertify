;; CertificateRegistry.clar
;; Core contract for managing biofuel certificate issuance and registry on Stacks blockchain.
;; This contract handles the creation, verification, transfer, and retirement of biofuel certificates,
;; ensuring transparency, uniqueness, and compliance in sustainable fuel trading.

;; Constants
(define-constant ERR-DUPLICATE-HASH u1) ;; Certificate hash already registered
(define-constant ERR-UNAUTHORIZED u2) ;; Caller not authorized
(define-constant ERR-INVALID-AMOUNT u3) ;; Invalid volume or score
(define-constant ERR-NOT-FOUND u4) ;; Certificate not found
(define-constant ERR-ALREADY-RETIRED u5) ;; Certificate already retired
(define-constant ERR-INVALID-METADATA u6) ;; Metadata too long or invalid
(define-constant ERR-PAUSED u7) ;; Contract paused
(define-constant ERR-INVALID-VERIFIER u8) ;; Invalid verifier
(define-constant ERR-COMPLIANCE-FAIL u9) ;; Compliance check failed
(define-constant MAX-METADATA-LEN u500) ;; Max length for metadata strings
(define-constant MIN-GHG-REDUCTION u20) ;; Minimum GHG reduction percentage for compliance
(define-constant CONTRACT-OWNER tx-sender) ;; Deployer is initial owner

;; Data Variables
(define-data-var contract-paused bool false)
(define-data-var admin principal CONTRACT-OWNER)
(define-data-var certificate-counter uint u0)

;; Data Maps
(define-map certificates
  { certificate-id: uint }
  {
    hash: (buff 32), ;; Unique SHA-256 hash of proof documents
    producer: principal, ;; Issuer of the certificate
    volume: uint, ;; Biofuel volume in liters
    biofuel-type: (string-utf8 50), ;; e.g., "Biodiesel", "Sustainable Aviation Fuel"
    ghg-reduction: uint, ;; Percentage reduction (e.g., u80 for 80%)
    production-date: uint, ;; Block height or timestamp
    location: (string-utf8 100), ;; Production location
    metadata: (string-utf8 500), ;; Additional details
    owner: principal, ;; Current owner
    retired: bool, ;; Whether retired (burned)
    retirement-reason: (optional (string-utf8 200)), ;; Reason for retirement
    timestamp: uint ;; Issuance timestamp
  }
)

(define-map hash-to-id
  { hash: (buff 32) }
  { certificate-id: uint }
)

(define-map verifiers
  { verifier: principal }
  { active: bool, added-by: principal, added-at: uint }
)

(define-map compliance-logs
  { certificate-id: uint, log-id: uint }
  {
    verifier: principal,
    status: bool, ;; Passed or failed
    notes: (string-utf8 200),
    timestamp: uint
  }
)

(define-map collaborators
  { certificate-id: uint, collaborator: principal }
  {
    role: (string-utf8 50), ;; e.g., "Auditor", "Trader"
    permissions: (list 5 (string-utf8 20)), ;; e.g., "view", "transfer"
    added-at: uint
  }
)

(define-map versions
  { certificate-id: uint, version: uint }
  {
    updated-hash: (buff 32),
    changes: (string-utf8 200),
    timestamp: uint
  }
)

(define-map licenses
  { certificate-id: uint, licensee: principal }
  {
    expiry: uint, ;; Block height
    terms: (string-utf8 200),
    active: bool
  }
)

;; Private Functions
(define-private (is-admin (caller principal))
  (is-eq caller (var-get admin))
)

(define-private (increment-counter)
  (let ((current (var-get certificate-counter)))
    (var-set certificate-counter (+ current u1))
    (+ current u1)
  )
)

(define-private (check-compliance (ghg uint))
  (>= ghg MIN-GHG-REDUCTION)
)

;; Public Functions

(define-public (pause-contract)
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-paused true)
    (ok true)
  )
)

(define-public (unpause-contract)
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set contract-paused false)
    (ok true)
  )
)

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)

(define-public (add-verifier (verifier principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (map-set verifiers {verifier: verifier} {active: true, added-by: tx-sender, added-at: block-height})
    (ok true)
  )
)

(define-public (remove-verifier (verifier principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (map-set verifiers {verifier: verifier} {active: false, added-by: tx-sender, added-at: block-height})
    (ok true)
  )
)

(define-public (issue-certificate
  (hash (buff 32))
  (volume uint)
  (biofuel-type (string-utf8 50))
  (ghg-reduction uint)
  (location (string-utf8 100))
  (metadata (string-utf8 500)))
  (begin
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (is-none (map-get? hash-to-id {hash: hash})) (err ERR-DUPLICATE-HASH))
    (asserts! (> volume u0) (err ERR-INVALID-AMOUNT))
    (asserts! (check-compliance ghg-reduction) (err ERR-COMPLIANCE-FAIL))
    (asserts! (<= (len metadata) MAX-METADATA-LEN) (err ERR-INVALID-METADATA))
    (let
      (
        (cert-id (increment-counter))
        (timestamp block-height)
      )
      (map-set certificates
        {certificate-id: cert-id}
        {
          hash: hash,
          producer: tx-sender,
          volume: volume,
          biofuel-type: biofuel-type,
          ghg-reduction: ghg-reduction,
          production-date: timestamp,
          location: location,
          metadata: metadata,
          owner: tx-sender,
          retired: false,
          retirement-reason: none,
          timestamp: timestamp
        }
      )
      (map-set hash-to-id {hash: hash} {certificate-id: cert-id})
      (ok cert-id)
    )
  )
)

(define-public (transfer-certificate (cert-id uint) (new-owner principal))
  (let
    (
      (cert (unwrap! (map-get? certificates {certificate-id: cert-id}) (err ERR-NOT-FOUND)))
    )
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (is-eq (get owner cert) tx-sender) (err ERR-UNAUTHORIZED))
    (asserts! (not (get retired cert)) (err ERR-ALREADY-RETIRED))
    (map-set certificates
      {certificate-id: cert-id}
      (merge cert {owner: new-owner})
    )
    (ok true)
  )
)

(define-public (retire-certificate (cert-id uint) (reason (string-utf8 200)))
  (let
    (
      (cert (unwrap! (map-get? certificates {certificate-id: cert-id}) (err ERR-NOT-FOUND)))
    )
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (is-eq (get owner cert) tx-sender) (err ERR-UNAUTHORIZED))
    (asserts! (not (get retired cert)) (err ERR-ALREADY-RETIRED))
    (map-set certificates
      {certificate-id: cert-id}
      (merge cert {retired: true, retirement-reason: (some reason)})
    )
    (ok true)
  )
)

(define-public (add-collaborator (cert-id uint) (collaborator principal) (role (string-utf8 50)) (permissions (list 5 (string-utf8 20))))
  (let
    (
      (cert (unwrap! (map-get? certificates {certificate-id: cert-id}) (err ERR-NOT-FOUND)))
    )
    (asserts! (is-eq (get owner cert) tx-sender) (err ERR-UNAUTHORIZED))
    (map-set collaborators
      {certificate-id: cert-id, collaborator: collaborator}
      {role: role, permissions: permissions, added-at: block-height}
    )
    (ok true)
  )
)

(define-public (log-compliance (cert-id uint) (status bool) (notes (string-utf8 200)))
  (let
    (
      (cert (unwrap! (map-get? certificates {certificate-id: cert-id}) (err ERR-NOT-FOUND)))
      (verifier-info (unwrap! (map-get? verifiers {verifier: tx-sender}) (err ERR-INVALID-VERIFIER)))
    )
    (asserts! (get active verifier-info) (err ERR-INVALID-VERIFIER))
    ;; For simplicity, assume log-id is certificate-counter or separate counter; here use cert-id for log-id placeholder
    (map-set compliance-logs
      {certificate-id: cert-id, log-id: (var-get certificate-counter)}
      {verifier: tx-sender, status: status, notes: notes, timestamp: block-height}
    )
    (ok true)
  )
)

(define-public (register-version (cert-id uint) (version uint) (new-hash (buff 32)) (changes (string-utf8 200)))
  (let
    (
      (cert (unwrap! (map-get? certificates {certificate-id: cert-id}) (err ERR-NOT-FOUND)))
    )
    (asserts! (is-eq (get owner cert) tx-sender) (err ERR-UNAUTHORIZED))
    (map-set versions
      {certificate-id: cert-id, version: version}
      {updated-hash: new-hash, changes: changes, timestamp: block-height}
    )
    (ok true)
  )
)

(define-public (grant-license (cert-id uint) (licensee principal) (duration uint) (terms (string-utf8 200)))
  (let
    (
      (cert (unwrap! (map-get? certificates {certificate-id: cert-id}) (err ERR-NOT-FOUND)))
    )
    (asserts! (is-eq (get owner cert) tx-sender) (err ERR-UNAUTHORIZED))
    (map-set licenses
      {certificate-id: cert-id, licensee: licensee}
      {expiry: (+ block-height duration), terms: terms, active: true}
    )
    (ok true)
  )
)

;; Read-Only Functions

(define-read-only (get-certificate-details (cert-id uint))
  (map-get? certificates {certificate-id: cert-id})
)

(define-read-only (get-certificate-by-hash (hash (buff 32)))
  (let ((id-opt (map-get? hash-to-id {hash: hash})))
    (match id-opt id (get-certificate-details id) none)
  )
)

(define-read-only (verify-ownership (cert-id uint) (owner principal))
  (let ((cert (map-get? certificates {certificate-id: cert-id})))
    (ok (and (is-some cert) (is-eq (get owner (unwrap! cert err-not-found)) owner)))
  )
)

(define-read-only (is-contract-paused)
  (var-get contract-paused)
)

(define-read-only (get-admin)
  (var-get admin)
)

(define-read-only (get-verifier-status (verifier principal))
  (map-get? verifiers {verifier: verifier})
)

(define-read-only (get-compliance-log (cert-id uint) (log-id uint))
  (map-get? compliance-logs {certificate-id: cert-id, log-id: log-id})
)

(define-read-only (get-collaborator (cert-id uint) (collaborator principal))
  (map-get? collaborators {certificate-id: cert-id, collaborator: collaborator})
)

(define-read-only (get-version (cert-id uint) (version uint))
  (map-get? versions {certificate-id: cert-id, version: version})
)

(define-read-only (get-license (cert-id uint) (licensee principal))
  (map-get? licenses {certificate-id: cert-id, licensee: licensee})
)