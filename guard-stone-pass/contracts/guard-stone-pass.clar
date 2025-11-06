;; GuardStonePass - Privacy-Preserving Decentralized Identity and Reputation System
;; A system for verifiable credentials and reputation without revealing personal data

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-authorized (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-not-found (err u103))
(define-constant err-invalid-commitment (err u104))
(define-constant err-invalid-proof (err u105))
(define-constant err-badge-revoked (err u106))
(define-constant err-insufficient-reputation (err u107))

;; Data Variables
(define-data-var next-badge-id uint u1)
(define-data-var next-anchor-id uint u1)
(define-data-var min-reputation-score uint u0)

;; Identity Anchor Structure
;; Cryptographic commitment representing user's identity without revealing personal data
(define-map identity-anchors
    { anchor-id: uint }
    {
        owner: principal,
        commitment-hash: (buff 32),
        created-at: uint,
        is-active: bool
    }
)

;; User anchor lookup
(define-map user-anchors
    { user: principal }
    { anchor-id: uint }
)

;; Badge Registry
;; Verifiable credentials issued through attestation contracts
(define-map badges
    { badge-id: uint }
    {
        badge-type: (string-ascii 50),
        issuer: principal,
        recipient-anchor: uint,
        metadata-uri: (string-ascii 256),
        proof-hash: (buff 32),
        issued-at: uint,
        expires-at: (optional uint),
        is-revoked: bool
    }
)

;; Badge Type Registry
(define-map badge-types
    { badge-type: (string-ascii 50) }
    {
        name: (string-ascii 100),
        issuer: principal,
        reputation-weight: uint,
        is-active: bool
    }
)

;; Reputation Scores
;; Anonymous aggregation of achievements
(define-map reputation-scores
    { anchor-id: uint }
    {
        total-score: uint,
        badge-count: uint,
        last-updated: uint
    }
)

;; Badge counts by type for each anchor
(define-map anchor-badge-types
    { anchor-id: uint, badge-type: (string-ascii 50) }
    { count: uint }
)

;; Authorized Badge Issuers
(define-map authorized-issuers
    { issuer: principal }
    { is-authorized: bool, authorized-at: uint }
)

;; Verification Requests (for commit-reveal schemes)
(define-map verification-commitments
    { commitment: (buff 32) }
    {
        requester: principal,
        created-at: uint,
        revealed: bool
    }
)

;; Read-only functions

;; Get identity anchor details
(define-read-only (get-identity-anchor (anchor-id uint))
    (map-get? identity-anchors { anchor-id: anchor-id })
)

;; Get user's anchor ID
(define-read-only (get-user-anchor (user principal))
    (map-get? user-anchors { user: user })
)

;; Get badge details
(define-read-only (get-badge (badge-id uint))
    (map-get? badges { badge-id: badge-id })
)

;; Get badge type information
(define-read-only (get-badge-type (badge-type (string-ascii 50)))
    (map-get? badge-types { badge-type: badge-type })
)

;; Get reputation score for an anchor
(define-read-only (get-reputation-score (anchor-id uint))
    (default-to 
        { total-score: u0, badge-count: u0, last-updated: u0 }
        (map-get? reputation-scores { anchor-id: anchor-id })
    )
)

;; Get badge count by type for an anchor
(define-read-only (get-anchor-badge-type-count (anchor-id uint) (badge-type (string-ascii 50)))
    (default-to 
        u0
        (get count (map-get? anchor-badge-types { anchor-id: anchor-id, badge-type: badge-type }))
    )
)

;; Check if issuer is authorized
(define-read-only (is-authorized-issuer (issuer principal))
    (default-to 
        false
        (get is-authorized (map-get? authorized-issuers { issuer: issuer }))
    )
)

;; Verify if anchor meets minimum reputation
(define-read-only (meets-reputation-threshold (anchor-id uint))
    (let ((score (get total-score (get-reputation-score anchor-id))))
        (>= score (var-get min-reputation-score))
    )
)

;; Check verification commitment
(define-read-only (get-verification-commitment (commitment (buff 32)))
    (map-get? verification-commitments { commitment: commitment })
)

;; Public functions

;; Create Identity Anchor
;; Users create a cryptographic commitment representing their identity
(define-public (create-identity-anchor (commitment-hash (buff 32)))
    (let
        (
            (anchor-id (var-get next-anchor-id))
            (existing-anchor (map-get? user-anchors { user: tx-sender }))
        )
        (asserts! (is-none existing-anchor) err-already-exists)
        (asserts! (> (len commitment-hash) u0) err-invalid-commitment)
        
        (map-set identity-anchors
            { anchor-id: anchor-id }
            {
                owner: tx-sender,
                commitment-hash: commitment-hash,
                created-at: block-height,
                is-active: true
            }
        )
        
        (map-set user-anchors
            { user: tx-sender }
            { anchor-id: anchor-id }
        )
        
        (map-set reputation-scores
            { anchor-id: anchor-id }
            {
                total-score: u0,
                badge-count: u0,
                last-updated: block-height
            }
        )
        
        (var-set next-anchor-id (+ anchor-id u1))
        (ok anchor-id)
    )
)

;; Update Identity Anchor Commitment
(define-public (update-anchor-commitment (new-commitment-hash (buff 32)))
    (let
        (
            (user-anchor-data (unwrap! (map-get? user-anchors { user: tx-sender }) err-not-found))
            (anchor-id (get anchor-id user-anchor-data))
            (anchor (unwrap! (map-get? identity-anchors { anchor-id: anchor-id }) err-not-found))
        )
        (asserts! (is-eq (get owner anchor) tx-sender) err-not-authorized)
        (asserts! (> (len new-commitment-hash) u0) err-invalid-commitment)
        
        (map-set identity-anchors
            { anchor-id: anchor-id }
            (merge anchor { commitment-hash: new-commitment-hash })
        )
        (ok true)
    )
)

;; Register Badge Type
(define-public (register-badge-type 
    (badge-type (string-ascii 50)) 
    (name (string-ascii 100))
    (reputation-weight uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (is-none (map-get? badge-types { badge-type: badge-type })) err-already-exists)
        
        (map-set badge-types
            { badge-type: badge-type }
            {
                name: name,
                issuer: tx-sender,
                reputation-weight: reputation-weight,
                is-active: true
            }
        )
        (ok true)
    )
)

;; Authorize Badge Issuer
(define-public (authorize-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        
        (map-set authorized-issuers
            { issuer: issuer }
            {
                is-authorized: true,
                authorized-at: block-height
            }
        )
        (ok true)
    )
)

;; Revoke Issuer Authorization
(define-public (revoke-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        
        (map-set authorized-issuers
            { issuer: issuer }
            {
                is-authorized: false,
                authorized-at: block-height
            }
        )
        (ok true)
    )
)

;; Issue Badge
;; Authorized issuers can issue verifiable badges to identity anchors
(define-public (issue-badge
    (recipient-anchor uint)
    (badge-type (string-ascii 50))
    (metadata-uri (string-ascii 256))
    (proof-hash (buff 32))
    (expires-at (optional uint)))
    (let
        (
            (badge-id (var-get next-badge-id))
            (badge-type-data (unwrap! (map-get? badge-types { badge-type: badge-type }) err-not-found))
            (anchor (unwrap! (map-get? identity-anchors { anchor-id: recipient-anchor }) err-not-found))
            (current-reputation (get-reputation-score recipient-anchor))
            (reputation-weight (get reputation-weight badge-type-data))
            (current-badge-type-count (get-anchor-badge-type-count recipient-anchor badge-type))
        )
        (asserts! (is-authorized-issuer tx-sender) err-not-authorized)
        (asserts! (get is-active badge-type-data) err-not-found)
        (asserts! (get is-active anchor) err-not-found)
        (asserts! (> (len proof-hash) u0) err-invalid-proof)
        
        ;; Create badge
        (map-set badges
            { badge-id: badge-id }
            {
                badge-type: badge-type,
                issuer: tx-sender,
                recipient-anchor: recipient-anchor,
                metadata-uri: metadata-uri,
                proof-hash: proof-hash,
                issued-at: block-height,
                expires-at: expires-at,
                is-revoked: false
            }
        )
        
        ;; Update reputation score
        (map-set reputation-scores
            { anchor-id: recipient-anchor }
            {
                total-score: (+ (get total-score current-reputation) reputation-weight),
                badge-count: (+ (get badge-count current-reputation) u1),
                last-updated: block-height
            }
        )
        
        ;; Update badge type count
        (map-set anchor-badge-types
            { anchor-id: recipient-anchor, badge-type: badge-type }
            { count: (+ current-badge-type-count u1) }
        )
        
        (var-set next-badge-id (+ badge-id u1))
        (ok badge-id)
    )
)

;; Revoke Badge
(define-public (revoke-badge (badge-id uint))
    (let
        (
            (badge (unwrap! (map-get? badges { badge-id: badge-id }) err-not-found))
            (badge-type-data (unwrap! (map-get? badge-types { badge-type: (get badge-type badge) }) err-not-found))
            (recipient-anchor (get recipient-anchor badge))
            (current-reputation (get-reputation-score recipient-anchor))
            (reputation-weight (get reputation-weight badge-type-data))
        )
        (asserts! (is-eq tx-sender (get issuer badge)) err-not-authorized)
        (asserts! (not (get is-revoked badge)) err-badge-revoked)
        
        ;; Revoke badge
        (map-set badges
            { badge-id: badge-id }
            (merge badge { is-revoked: true })
        )
        
        ;; Update reputation score (subtract weight)
        (map-set reputation-scores
            { anchor-id: recipient-anchor }
            {
                total-score: (if (>= (get total-score current-reputation) reputation-weight)
                    (- (get total-score current-reputation) reputation-weight)
                    u0),
                badge-count: (if (> (get badge-count current-reputation) u0)
                    (- (get badge-count current-reputation) u1)
                    u0),
                last-updated: block-height
            }
        )
        
        (ok true)
    )
)

;; Commit Verification Request (Part of commit-reveal scheme)
(define-public (commit-verification (commitment (buff 32)))
    (begin
        (asserts! (is-none (map-get? verification-commitments { commitment: commitment })) err-already-exists)
        
        (map-set verification-commitments
            { commitment: commitment }
            {
                requester: tx-sender,
                created-at: block-height,
                revealed: false
            }
        )
        (ok true)
    )
)

;; Reveal Verification (Part of commit-reveal scheme)
(define-public (reveal-verification (commitment (buff 32)) (proof-data (buff 32)))
    (let
        (
            (commitment-data (unwrap! (map-get? verification-commitments { commitment: commitment }) err-not-found))
        )
        (asserts! (is-eq tx-sender (get requester commitment-data)) err-not-authorized)
        (asserts! (not (get revealed commitment-data)) err-already-exists)
        
        ;; Simple proof verification (hash matching)
        (asserts! (is-eq commitment (sha256 proof-data)) err-invalid-proof)
        
        (map-set verification-commitments
            { commitment: commitment }
            (merge commitment-data { revealed: true })
        )
        (ok true)
    )
)

;; Set Minimum Reputation Score
(define-public (set-min-reputation (min-score uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set min-reputation-score min-score)
        (ok true)
    )
)

;; Deactivate Identity Anchor
(define-public (deactivate-anchor)
    (let
        (
            (user-anchor-data (unwrap! (map-get? user-anchors { user: tx-sender }) err-not-found))
            (anchor-id (get anchor-id user-anchor-data))
            (anchor (unwrap! (map-get? identity-anchors { anchor-id: anchor-id }) err-not-found))
        )
        (asserts! (is-eq (get owner anchor) tx-sender) err-not-authorized)
        
        (map-set identity-anchors
            { anchor-id: anchor-id }
            (merge anchor { is-active: false })
        )
        (ok true)
    )
)

;; Reactivate Identity Anchor
(define-public (reactivate-anchor)
    (let
        (
            (user-anchor-data (unwrap! (map-get? user-anchors { user: tx-sender }) err-not-found))
            (anchor-id (get anchor-id user-anchor-data))
            (anchor (unwrap! (map-get? identity-anchors { anchor-id: anchor-id }) err-not-found))
        )
        (asserts! (is-eq (get owner anchor) tx-sender) err-not-authorized)
        
        (map-set identity-anchors
            { anchor-id: anchor-id }
            (merge anchor { is-active: true })
        )
        (ok true)
    )
)
