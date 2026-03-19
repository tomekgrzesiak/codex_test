# Policy Evaluation System for Package Scans

Design for a policy evaluation system that scans software packages against malware and vulnerabilities.

---

## Part 1: System Design Overview

### Core Concepts

**Three-layer flow:**
```
Scan Result (from scanner) → Policy Engine → Verdict (PASS/WARN/BLOCK)
```

---

### Data Models

#### Scan Result (normalized from any scanner)
```go
type ScanResult struct {
    ID           string
    Package      Package            // name, version, ecosystem
    ScannedAt    time.Time
    CVEs         []CVEFinding       // ID, severity, CVSS, fixedIn
    Licenses     []LicenseFinding   // SPDX identifiers
    Malware      []MalwareFinding   // signature, family, confidence score
    Dependencies []DependencyFinding // transitive deps with publish dates
}
```

#### Policy and Rules
```go
type Policy struct {
    ID      string
    Name    string
    Scope   PolicyScope  // which ecosystems/package globs it applies to
    Rules   []Rule
    Mode    PolicyMode   // ENFORCING (blocks) or ADVISORY (reports only)
}

type Rule struct {
    ID       string
    Type     RuleType     // cve_threshold, license_deny_list, malware, dependency_age, ...
    Severity RuleSeverity // BLOCK, WARN, INFO
    Config   RuleConfig   // type-specific config struct
}
```

#### Rule Type Configs

| Rule Type | Config Fields |
|---|---|
| `cve_threshold` | `minSeverity`, `minCVSS`, `ignoreIfFixed`, `ignoreCVEs` |
| `license_deny_list` | `licenses` (SPDX list) |
| `license_allow_list` | `licenses` (only these allowed) |
| `malware` | `minConfidence` (0.0–1.0), `families` |
| `dependency_age` | `maxAgeDays`, `transitiveOnly` |

---

### Evaluation Engine

The engine is built around a simple **Evaluator interface** — one per rule type:

```go
type Evaluator interface {
    Type() RuleType
    Evaluate(ctx context.Context, result ScanResult, config RuleConfig) ([]RuleViolation, error)
}
```

The engine loops over a policy's rules, calls the matching evaluator, aggregates violations, then computes an outcome:

```
violations with BLOCK severity + ENFORCING mode → OutcomeBlock
any violations                                  → OutcomeWarn
no violations                                   → OutcomePass
```

**Key:** adding a new rule type = implement one `Evaluator` + register it. No changes to the engine core.

---

### Integration Points

**Scan data ingestion** — scanner adapter interface normalizes different scanner formats (Trivy, Grype, Snyk, VirusTotal) into a common `ScanResult`:
```
POST /api/v1/scans          ← push from scanner
GET  /api/v1/scans/trigger  ← pull/trigger scan
```

**Verdict consumption:**
- `GET /api/v1/packages/{name}/{version}/verdict` — CI pipeline polls before deploying
- Outbound webhooks on BLOCK/WARN → Slack, Jira, PagerDuty
- Registry middleware gate — checks verdict before allowing package pull
- Append-only audit log for compliance

---

### Key Architectural Decisions

**1. Sync vs. async evaluation**
Start synchronous. Add a job queue (channel or DB-backed) when latency or policy complexity grows. The interface design doesn't change.

**2. Policy versioning**
Store a `PolicySnapshot` (full policy JSON) with each verdict. This is cheap and means you can always reproduce why a verdict was issued — essential for compliance audits.

**3. Custom engine vs. OPA**
The interface-based evaluator pattern is preferable when rule types are a bounded, known set and you want type-safe Go. OPA/Rego is worth it if policies need to be user-authored or updated at runtime without redeployment. The two aren't mutually exclusive — you can delegate specific rule types to OPA later.

**4. Policy scope matching**
Start with glob matching (`filepath.Match`) on package names and ecosystem strings. Add semver range matching (e.g., `Masterminds/semver`) only when version-specific policies are needed.

**5. Storage**
PostgreSQL (same as your current stack) for both policies and verdicts. Policies are config that changes infrequently; verdicts are append-only facts. A future migration to a dedicated policy store is easy given the repository interface pattern.

---

### Suggested Package Layout

```
internal/
  policy/
    model.go          ← Policy, Rule, Verdict types
    engine.go         ← Engine + Evaluator interface
    repository.go     ← PolicyRepository (postgres impl)
    evaluators/
      cve.go
      license.go
      malware.go
      dependency_age.go
  scan/
    model.go          ← ScanResult, findings
    repository.go     ← ScanRepository (postgres impl)
    adapters/
      trivy.go
      grype.go
```

---

## Part 2: Concrete Evaluator Implementations & API Design

### The Interface & Registry

```go
// internal/policy/engine.go

type RuleConfig interface {
    ruleConfigMarker() // sealed — only types in this package implement it
}

type Evaluator interface {
    Type() RuleType
    Evaluate(ctx context.Context, result ScanResult, cfg RuleConfig) ([]RuleViolation, error)
}

type Engine struct {
    evaluators map[RuleType]Evaluator
}

func NewEngine(evals ...Evaluator) *Engine {
    e := &Engine{evaluators: make(map[RuleType]Evaluator)}
    for _, ev := range evals {
        e.evaluators[ev.Type()] = ev
    }
    return e
}

func (e *Engine) Evaluate(ctx context.Context, policy Policy, result ScanResult) (Verdict, error) {
    v := Verdict{
        PolicyID:    policy.ID,
        ScanID:      result.ID,
        Package:     result.Package,
        EvaluatedAt: time.Now(),
    }
    for _, rule := range policy.Rules {
        ev, ok := e.evaluators[rule.Type]
        if !ok {
            return v, fmt.Errorf("no evaluator for rule type %q", rule.Type)
        }
        violations, err := ev.Evaluate(ctx, result, rule.Config)
        if err != nil {
            return v, fmt.Errorf("rule %s: %w", rule.ID, err)
        }
        for i := range violations {
            violations[i].RuleID = rule.ID
            violations[i].Severity = rule.Severity
        }
        v.Violations = append(v.Violations, violations...)
    }
    v.Outcome = computeOutcome(policy.Mode, v.Violations)
    return v, nil
}
```

---

### CVE Threshold Evaluator

```go
// internal/policy/evaluators/cve.go

type CVEThresholdConfig struct {
    MinSeverity   Severity // CRITICAL, HIGH, MEDIUM, LOW
    MinCVSS       float64  // 0.0–10.0; 0 means "don't check CVSS"
    IgnoreIfFixed bool     // waive CVEs that have a fix available
    IgnoreCVEs    []string // explicit allowlist of CVE IDs
}

func (CVEThresholdConfig) ruleConfigMarker() {}

type CVEEvaluator struct{}

func (CVEEvaluator) Type() RuleType { return RuleTypeCVEThreshold }

func (CVEEvaluator) Evaluate(_ context.Context, result ScanResult, cfg RuleConfig) ([]RuleViolation, error) {
    c, ok := cfg.(CVEThresholdConfig)
    if !ok {
        return nil, fmt.Errorf("expected CVEThresholdConfig, got %T", cfg)
    }

    ignored := make(map[string]bool, len(c.IgnoreCVEs))
    for _, id := range c.IgnoreCVEs {
        ignored[id] = true
    }

    var violations []RuleViolation
    for _, cve := range result.CVEs {
        if ignored[cve.ID] {
            continue
        }
        if c.IgnoreIfFixed && cve.FixedIn != "" {
            continue
        }
        severityHit := cve.Severity.AtLeast(c.MinSeverity)
        cvssHit := c.MinCVSS > 0 && cve.CVSS >= c.MinCVSS

        if severityHit || cvssHit {
            violations = append(violations, RuleViolation{
                Message: fmt.Sprintf("%s: severity=%s CVSS=%.1f fixedIn=%q",
                    cve.ID, cve.Severity, cve.CVSS, cve.FixedIn),
                Evidence: map[string]any{
                    "cve_id":   cve.ID,
                    "severity": cve.Severity,
                    "cvss":     cve.CVSS,
                    "fixed_in": cve.FixedIn,
                },
            })
        }
    }
    return violations, nil
}
```

---

### License Evaluator (deny + allow modes)

```go
// internal/policy/evaluators/license.go

type LicenseConfig struct {
    Mode     LicenseMode // DENY or ALLOW
    Licenses []string    // SPDX identifiers
}

func (LicenseConfig) ruleConfigMarker() {}

type LicenseMode string
const (
    LicenseModeDeny  LicenseMode = "DENY"
    LicenseModeAllow LicenseMode = "ALLOW"
)

type LicenseEvaluator struct{}

func (LicenseEvaluator) Type() RuleType { return RuleTypeLicense }

func (LicenseEvaluator) Evaluate(_ context.Context, result ScanResult, cfg RuleConfig) ([]RuleViolation, error) {
    c := cfg.(LicenseConfig)

    set := make(map[string]bool, len(c.Licenses))
    for _, l := range c.Licenses {
        set[strings.ToUpper(l)] = true
    }

    seen := make(map[string]bool) // deduplicate per-license violations
    var violations []RuleViolation

    for _, finding := range result.Licenses {
        key := strings.ToUpper(finding.License)
        if seen[key] {
            continue
        }
        var hit bool
        switch c.Mode {
        case LicenseModeDeny:
            hit = set[key]
        case LicenseModeAllow:
            hit = !set[key]
        }
        if hit {
            seen[key] = true
            violations = append(violations, RuleViolation{
                Message: fmt.Sprintf("license %q is %s", finding.License, c.Mode),
                Evidence: map[string]any{"license": finding.License, "mode": c.Mode},
            })
        }
    }
    return violations, nil
}
```

---

### Malware Evaluator

```go
// internal/policy/evaluators/malware.go

type MalwareConfig struct {
    MinConfidence float64  // 0.0–1.0; default 0.8
    Families      []string // empty = all families
}

func (MalwareConfig) ruleConfigMarker() {}

type MalwareEvaluator struct{}

func (MalwareEvaluator) Type() RuleType { return RuleTypeMalware }

func (MalwareEvaluator) Evaluate(_ context.Context, result ScanResult, cfg RuleConfig) ([]RuleViolation, error) {
    c := cfg.(MalwareConfig)
    minConf := c.MinConfidence
    if minConf == 0 {
        minConf = 0.8
    }

    familyFilter := make(map[string]bool, len(c.Families))
    for _, f := range c.Families {
        familyFilter[strings.ToLower(f)] = true
    }

    var violations []RuleViolation
    for _, m := range result.Malware {
        if len(familyFilter) > 0 && !familyFilter[strings.ToLower(m.Family)] {
            continue
        }
        if m.Confidence < minConf {
            continue
        }
        violations = append(violations, RuleViolation{
            Message: fmt.Sprintf("malware detected: family=%q signature=%s confidence=%.2f location=%s",
                m.Family, m.SignatureID, m.Confidence, m.Location),
            Evidence: map[string]any{
                "signature_id": m.SignatureID,
                "family":       m.Family,
                "confidence":   m.Confidence,
                "location":     m.Location,
            },
        })
    }
    return violations, nil
}
```

---

### Dependency Age Evaluator

```go
// internal/policy/evaluators/dependency_age.go

type DependencyAgeConfig struct {
    MaxAgeDays     int  // flag packages not updated in this many days
    TransitiveOnly bool // only check transitive deps
    DirectOnly     bool // only check direct deps
}

func (DependencyAgeConfig) ruleConfigMarker() {}

type DependencyAgeEvaluator struct {
    Now func() time.Time // injectable for testing
}

func (e DependencyAgeEvaluator) Type() RuleType { return RuleTypeDependencyAge }

func (e DependencyAgeEvaluator) Evaluate(_ context.Context, result ScanResult, cfg RuleConfig) ([]RuleViolation, error) {
    c := cfg.(DependencyAgeConfig)
    now := e.Now
    if now == nil {
        now = time.Now
    }

    var violations []RuleViolation
    for _, dep := range result.Dependencies {
        if c.TransitiveOnly && !dep.IsTransitive {
            continue
        }
        if c.DirectOnly && dep.IsTransitive {
            continue
        }
        ageDays := int(now().Sub(dep.PublishedAt).Hours() / 24)
        if ageDays > c.MaxAgeDays {
            violations = append(violations, RuleViolation{
                Message: fmt.Sprintf("%s@%s last published %d days ago (max %d)",
                    dep.Package.Name, dep.Package.Version, ageDays, c.MaxAgeDays),
                Evidence: map[string]any{
                    "package":      dep.Package.Name,
                    "version":      dep.Package.Version,
                    "age_days":     ageDays,
                    "published_at": dep.PublishedAt,
                },
            })
        }
    }
    return violations, nil
}
```

---

### Wiring It All Together

```go
// main.go (or wherever you bootstrap)

engine := policy.NewEngine(
    evaluators.CVEEvaluator{},
    evaluators.LicenseEvaluator{},
    evaluators.MalwareEvaluator{},
    evaluators.DependencyAgeEvaluator{},
)
```

---

## API Endpoint Design

### Resource Model

```
/api/v1/policies                               ← policy CRUD
/api/v1/policies/{id}/evaluate                 ← ad-hoc evaluation
/api/v1/scans                                  ← ingest scan results
/api/v1/scans/{id}/verdict                     ← verdict for a scan
/api/v1/packages/{eco}/{name}/{version}/verdict ← latest verdict by package
```

### Full Endpoint Table

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/policies` | List policies (filter by `?ecosystem=`, `?mode=`) |
| `POST` | `/api/v1/policies` | Create policy |
| `GET` | `/api/v1/policies/{id}` | Get policy |
| `PUT` | `/api/v1/policies/{id}` | Replace policy (creates new version) |
| `DELETE` | `/api/v1/policies/{id}` | Soft-delete policy |
| `POST` | `/api/v1/scans` | Ingest a scan result |
| `GET` | `/api/v1/scans/{id}` | Get raw scan result |
| `POST` | `/api/v1/scans/{id}/evaluate` | Evaluate scan against all matching policies |
| `GET` | `/api/v1/scans/{id}/verdict` | Get stored verdict for a scan |
| `GET` | `/api/v1/packages/{eco}/{name}/{version}/verdict` | Latest verdict (for CI polling) |

---

### Request/Response Shapes

**POST `/api/v1/policies`**
```json
{
  "name": "production-gate",
  "mode": "ENFORCING",
  "scope": {
    "ecosystems": ["npm", "pypi"],
    "package_globs": []
  },
  "rules": [
    {
      "type": "cve_threshold",
      "severity": "BLOCK",
      "config": {
        "min_severity": "HIGH",
        "min_cvss": 7.0,
        "ignore_if_fixed": false
      }
    },
    {
      "type": "license",
      "severity": "BLOCK",
      "config": {
        "mode": "DENY",
        "licenses": ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"]
      }
    },
    {
      "type": "malware",
      "severity": "BLOCK",
      "config": {
        "min_confidence": 0.75
      }
    }
  ]
}
```

**POST `/api/v1/scans/{id}/evaluate` → 200**
```json
{
  "scan_id": "scan_abc123",
  "evaluated_at": "2026-03-19T10:00:00Z",
  "verdicts": [
    {
      "policy_id": "pol_xyz",
      "policy_name": "production-gate",
      "outcome": "BLOCK",
      "violations": [
        {
          "rule_id": "rule_001",
          "severity": "BLOCK",
          "message": "CVE-2024-1234: severity=HIGH CVSS=8.1 fixedIn=\"\"",
          "evidence": {
            "cve_id": "CVE-2024-1234",
            "severity": "HIGH",
            "cvss": 8.1,
            "fixed_in": ""
          }
        }
      ]
    }
  ],
  "aggregate_outcome": "BLOCK"
}
```

**GET `/api/v1/packages/npm/lodash/4.17.20/verdict` → 200**
```json
{
  "package": { "ecosystem": "npm", "name": "lodash", "version": "4.17.20" },
  "scan_id": "scan_abc123",
  "scanned_at": "2026-03-19T09:55:00Z",
  "outcome": "BLOCK",
  "policy_count": 2,
  "violations_count": 1
}
```

---

### Handler Skeleton

```go
// internal/policy/handler.go

type Handler struct {
    engine      *Engine
    policyRepo  PolicyRepository
    scanRepo    ScanRepository
    verdictRepo VerdictRepository
}

func (h *Handler) EvaluateScan(w http.ResponseWriter, r *http.Request) {
    scanID := chi.URLParam(r, "id")

    result, err := h.scanRepo.GetByID(r.Context(), scanID)
    if err != nil {
        respondError(w, err)
        return
    }

    policies, err := h.policyRepo.MatchingPolicies(r.Context(), result.Package)
    if err != nil {
        respondError(w, err)
        return
    }

    resp := EvaluateResponse{ScanID: scanID, EvaluatedAt: time.Now()}
    for _, pol := range policies {
        verdict, err := h.engine.Evaluate(r.Context(), pol, result)
        if err != nil {
            respondError(w, err)
            return
        }
        _ = h.verdictRepo.Store(r.Context(), verdict)
        resp.Verdicts = append(resp.Verdicts, verdict)
    }
    resp.AggregateOutcome = aggregateOutcome(resp.Verdicts)

    respondJSON(w, http.StatusOK, resp)
}
```

---

### Policy Versioning on PUT

Rather than mutating in place, `PUT /api/v1/policies/{id}` bumps a version counter and records the old version in a `policy_versions` table:

```
policies                policy_versions
──────────────────      ─────────────────────────────
id                      policy_id  (FK → policies.id)
name                    version    (monotonic int)
active_version  ──────► snapshot   (JSONB — full policy at that version)
                        created_at
```

Verdicts store `policy_id + policy_version`, so you can always reconstruct exactly what rules were active when a verdict was issued.

---

### Scope-Matching Query

```go
// MatchingPolicies returns all active policies whose scope includes this package.
func (r *PostgresPolicyRepo) MatchingPolicies(ctx context.Context, pkg Package) ([]Policy, error) {
    // Load all active policies for the ecosystem (or global ones),
    // then filter package_globs in Go with filepath.Match.
    rows, err := r.db.Query(ctx, `
        SELECT id, name, mode, scope, rules, active_version
        FROM policies
        WHERE deleted_at IS NULL
          AND (scope->>'ecosystems' = '[]'
               OR scope->'ecosystems' ? $1)
    `, pkg.Ecosystem)
    // ... unmarshal + glob-filter ...
}
```
