import {
  Activity,
  Binary,
  CalendarClock,
  Clipboard,
  Database,
  ExternalLink,
  Fingerprint,
  Globe2,
  Network,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  Swords,
} from 'lucide-react'
import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import '../Workbench.css'


const API = '/api/v1'


function valueOrDash(value) {
  if (
    value === undefined
    || value === null
    || value === ''
  ) {
    return '—'
  }

  return String(value)
}


function formatDate(value) {
  if (!value) {
    return '—'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return String(value)
  }

  return date.toLocaleString()
}


function formatShortDate(value) {
  if (!value) {
    return '—'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return String(value)
  }

  return date.toLocaleDateString()
}


function firstArray(...values) {
  for (const value of values) {
    if (Array.isArray(value)) {
      return value
    }
  }

  return []
}


function normalizeInvestigation(data) {
  const results = data?.results ?? {}

  return {
    detectedType:
      data?.detected_type
      ?? data?.type
      ?? 'unknown',

    found: Boolean(data?.found),

    count:
      data?.result_count
      ?? 0,

    observables: firstArray(
      results.observables,
      data?.observables,
    ),

    indicators: firstArray(
      results.indicators,
      data?.indicators,
    ),

    vulnerability:
      results.vulnerability
      ?? data?.vulnerability
      ?? null,

    technique:
      results.attack_technique
      ?? data?.attack_technique
      ?? null,
  }
}


function normalizeObservableLookup(data) {
  if (!data) {
    return null
  }

  /*
   * Actual backend contract:
   *
   * {
   *   query,
   *   matches,
   *   observables: [
   *     {
   *       id,
   *       type,
   *       value,
   *       first_seen,
   *       last_seen,
   *       related_indicator_count,
   *       intelligence_summary,
   *       enrichments,
   *       returned,
   *       limit,
   *       offset,
   *       related_indicators
   *     }
   *   ]
   * }
   */

  const observable =
    Array.isArray(data.observables)
      ? data.observables[0]
      : data.observable ?? null

  if (!observable) {
    return null
  }

  return {
    observable,

    related: firstArray(
      observable.related_indicators,
      observable.indicators,
    ),

    enrichments: firstArray(
      observable.enrichments,
    ),

    total:
      observable.related_indicator_count
      ?? observable.relationship_count
      ?? 0,

    returned:
      observable.returned
      ?? observable.related_indicators?.length
      ?? 0,

    limit:
      observable.limit
      ?? 0,

    offset:
      observable.offset
      ?? 0,

    summary:
      observable.intelligence_summary
      ?? null,
  }
}


function summaryCount(items, name) {
  if (!Array.isArray(items)) {
    return 0
  }

  const match = items.find(
    (item) => (
      String(item?.name ?? '')
        .toLowerCase()
      === String(name).toLowerCase()
    ),
  )

  return Number(match?.count ?? 0)
}


function generateKql(type, query) {
  const escaped =
    query.replace(/"/g, '\\"')

  if (type === 'ip') {
    return `let IOC = "${escaped}";
DeviceNetworkEvents
| where RemoteIP == IOC
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc`
  }

  if (type === 'domain') {
    return `let IOC = "${escaped}";
DeviceNetworkEvents
| where RemoteUrl has IOC
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by Timestamp desc`
  }

  if (type === 'url') {
    return `let IOC = "${escaped}";
DeviceNetworkEvents
| where RemoteUrl == IOC or RemoteUrl has IOC
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by Timestamp desc`
  }

  if (
    type === 'hash'
    || type === 'sha256'
    || type === 'sha1'
    || type === 'md5'
  ) {
    return `let IOC = "${escaped}";
DeviceFileEvents
| where SHA256 == IOC or SHA1 == IOC or MD5 == IOC
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5
| order by Timestamp desc`
  }

  return `// Connect Microsoft Defender XDR to hunt this intelligence object.
// Query: ${escaped}`
}


function SectionHeading({
  icon: Icon,
  title,
  description,
}) {
  return (
    <div className="wb-panel-heading">
      <div>
        <h3>{title}</h3>

        {description && (
          <p>{description}</p>
        )}
      </div>

      {Icon && (
        <div className="wb-panel-icon">
          <Icon size={17} />
        </div>
      )}
    </div>
  )
}


function DetailRow({
  label,
  value,
}) {
  return (
    <div className="wb-detail-row">
      <span>{label}</span>
      <strong>{valueOrDash(value)}</strong>
    </div>
  )
}


function MicrosoftContext({
  detectedType,
  query,
}) {
  const [copied, setCopied] =
    useState(false)

  const kql = useMemo(
    () => generateKql(
      detectedType,
      query,
    ),
    [detectedType, query],
  )


  async function copyKql() {
    try {
      await navigator.clipboard.writeText(kql)

      setCopied(true)

      window.setTimeout(() => {
        setCopied(false)
      }, 1600)
    } catch {
      setCopied(false)
    }
  }


  return (
    <section className="wb-panel">
      <SectionHeading
        icon={Shield}
        title="Microsoft Security"
        description="Organizational security context"
      />

      <div className="wb-microsoft-state">
        <span />
        Defender XDR is not connected
      </div>

      <div className="wb-microsoft-metrics">
        <div className="wb-microsoft-metric">
          <span>Tenant sightings</span>
          <strong>—</strong>
        </div>

        <div className="wb-microsoft-metric">
          <span>Related alerts</span>
          <strong>—</strong>
        </div>

        <div className="wb-microsoft-metric">
          <span>Related incidents</span>
          <strong>—</strong>
        </div>

        <div className="wb-microsoft-metric">
          <span>Affected devices</span>
          <strong>—</strong>
        </div>
      </div>

      <div className="wb-kql">
        <pre>{kql}</pre>
      </div>

      <button
        className="wb-copy"
        onClick={copyKql}
      >
        <Clipboard size={14} />

        {copied
          ? 'Copied'
          : 'Copy hunting query'}
      </button>
    </section>
  )
}


function ObservableWorkbench({
  query,
  investigation,
  lookup,
}) {
  const investigationObservable =
    investigation.observables[0]
    ?? {}

  const observable =
    lookup?.observable
    ?? investigationObservable

  const enrichment =
    lookup?.enrichments?.[0]
    ?? observable.enrichments?.[0]
    ?? investigationObservable.enrichments?.[0]
    ?? {}

  const related =
    lookup?.related
    ?? []

  const summary =
    lookup?.summary
    ?? {}

  const relationshipCount =
    lookup?.total
    ?? observable.related_indicator_count
    ?? investigationObservable.related_indicator_count
    ?? related.length

  /*
   * Use aggregate intelligence_summary for totals.
   * This is important because related_indicators is paginated.
   * We must not calculate global online/offline counts from
   * only the five or twenty-five rows currently returned.
   */
  const onlineCount =
    summaryCount(
      summary.statuses,
      'online',
    )

  const offlineCount =
    summaryCount(
      summary.statuses,
      'offline',
    )

  const statusTotal =
    Array.isArray(summary.statuses)
      ? summary.statuses.reduce(
          (total, item) => (
            total + Number(item?.count ?? 0)
          ),
          0,
        )
      : 0

  const sourceSummary =
    firstArray(summary.sources)

  const threatSummary =
    firstArray(summary.threat_types)

  const tagSummary =
    firstArray(summary.tags)

  const country =
    enrichment.country
    ?? observable.country
    ?? '—'

  const continent =
    enrichment.continent
    ?? observable.continent
    ?? '—'

  const asn =
    enrichment.asn
    ?? observable.asn
    ?? '—'

  const network =
    enrichment.as_name
    ?? observable.as_name
    ?? '—'

  const asDomain =
    enrichment.as_domain
    ?? observable.as_domain
    ?? '—'

  const provider =
    enrichment.provider
    ?? '—'

  const detectedType =
    investigation.detectedType

  const timeline = related
    .filter((indicator) => (
      indicator.last_seen
      || indicator.first_seen
    ))
    .slice(0, 8)


  return (
    <>
      <section className="wb-object-header">
        <div className="wb-object-top">
          <div>
            <span className="wb-object-kind">
              <Globe2 size={13} />
              {detectedType}
            </span>

            <h2>
              {observable.value ?? query}
            </h2>

            <p className="wb-object-subtitle">
              Correlated observable intelligence
            </p>
          </div>

          <span className="wb-local-match">
            Local intelligence match
          </span>
        </div>

        <div className="wb-kpis">
          <div className="wb-kpi">
            <span>Relationships</span>
            <strong>
              {Number(
                relationshipCount || 0,
              ).toLocaleString()}
            </strong>
          </div>

          <div className="wb-kpi">
            <span>Primary source</span>
            <strong>
              {
                sourceSummary[0]?.name
                ?? related[0]?.source
                ?? '—'
              }
            </strong>
          </div>

          <div className="wb-kpi">
            <span>Country</span>
            <strong>{country}</strong>
          </div>

          <div className="wb-kpi">
            <span>ASN</span>
            <strong>{asn}</strong>
          </div>

          <div className="wb-kpi">
            <span>Last observed</span>
            <strong>
              {formatShortDate(
                observable.last_seen,
              )}
            </strong>
          </div>
        </div>
      </section>

      <div className="wb-layout">
        <div className="wb-column">
          <section className="wb-panel">
            <SectionHeading
              icon={Radar}
              title="Intelligence Summary"
              description="Aggregated intelligence across all correlated relationships"
            />

            <p className="wb-summary-text">
              This {detectedType} is associated with{' '}
              <strong>
                {Number(
                  relationshipCount || 0,
                ).toLocaleString()}
              </strong>{' '}
              locally correlated indicator
              relationships.

              {' '}

              The infrastructure metadata below
              describes hosting or network context;
              it is not by itself a maliciousness
              assessment.
            </p>

            <div className="wb-stat-grid">
              <div className="wb-stat">
                <span>
                  Online indicators
                </span>

                <strong className="online">
                  {onlineCount.toLocaleString()}
                </strong>
              </div>

              <div className="wb-stat">
                <span>
                  Offline indicators
                </span>

                <strong>
                  {offlineCount.toLocaleString()}
                </strong>
              </div>

              <div className="wb-stat">
                <span>
                  Total classified
                </span>

                <strong>
                  {statusTotal.toLocaleString()}
                </strong>
              </div>
            </div>

            {sourceSummary.length > 0 && (
              <div className="wb-detail-list">
                <DetailRow
                  label="Sources"
                  value={
                    sourceSummary
                      .map(
                        (item) => (
                          `${item.name} (${item.count})`
                        ),
                      )
                      .join(', ')
                  }
                />
              </div>
            )}

            {threatSummary.length > 0 && (
              <div className="wb-detail-list">
                <DetailRow
                  label="Threat types"
                  value={
                    threatSummary
                      .map(
                        (item) => (
                          `${item.name} (${item.count})`
                        ),
                      )
                      .join(', ')
                  }
                />
              </div>
            )}

            {tagSummary.length > 0 && (
              <div className="wb-tags">
                {tagSummary
                  .slice(0, 14)
                  .map((tag) => (
                    <span
                      className="wb-tag"
                      key={tag.name}
                    >
                      {tag.name}
                      {' · '}
                      {tag.count}
                    </span>
                  ))}
              </div>
            )}
          </section>

          <section className="wb-panel">
            <SectionHeading
              icon={Network}
              title="Related Indicators"
              description={
                `${Number(
                  relationshipCount || 0,
                ).toLocaleString()} total relationships · `
                + `${related.length} currently loaded`
              }
            />

            {related.length > 0 ? (
              <div className="wb-related">
                <div className="wb-related-header">
                  <span>Status</span>
                  <span>Indicator</span>
                  <span>Threat type</span>
                  <span>Observed</span>
                </div>

                {related.map(
                  (indicator, index) => (
                    <div
                      className="wb-related-row"
                      key={
                        indicator.id
                        ?? indicator.source_id
                        ?? `${indicator.value}-${index}`
                      }
                    >
                      <span
                        className={
                          `wb-status ${
                            String(
                              indicator.status
                              ?? '',
                            ).toLowerCase()
                          }`
                        }
                      >
                        {
                          indicator.status
                          ?? 'unknown'
                        }
                      </span>

                      <span
                        className="wb-related-value"
                        title={
                          indicator.value
                        }
                      >
                        {
                          indicator.value
                          ?? '—'
                        }
                      </span>

                      <span className="wb-related-value">
                        {
                          indicator.threat_type
                          ?? '—'
                        }
                      </span>

                      <span className="wb-related-value">
                        {formatDate(
                          indicator.last_seen
                          ?? indicator.first_seen,
                        )}
                      </span>
                    </div>
                  ),
                )}
              </div>
            ) : (
              <p className="wb-summary-text">
                No related indicator records were
                returned in this page of the lookup.
              </p>
            )}
          </section>

          <section className="wb-panel">
            <SectionHeading
              icon={CalendarClock}
              title="Observation Timeline"
              description="Recent related source observations"
            />

            {timeline.length > 0 ? (
              <div className="wb-timeline">
                {timeline.map(
                  (indicator, index) => (
                    <div
                      className="wb-timeline-item"
                      key={
                        indicator.id
                        ?? `${indicator.value}-${index}`
                      }
                    >
                      <div className="wb-timeline-date">
                        {formatDate(
                          indicator.last_seen
                          ?? indicator.first_seen,
                        )}
                      </div>

                      <div className="wb-timeline-marker" />

                      <div className="wb-timeline-content">
                        <strong>
                          {
                            indicator.source
                            ?? 'Source'
                          } observation
                        </strong>

                        <span>
                          {
                            indicator.status
                            ?? 'unknown'
                          }

                          {' · '}

                          {
                            indicator.threat_type
                            ?? 'indicator'
                          }
                        </span>
                      </div>
                    </div>
                  ),
                )}
              </div>
            ) : (
              <p className="wb-summary-text">
                No timestamped related indicators
                were returned.
              </p>
            )}
          </section>
        </div>

        <aside className="wb-column">
          <section className="wb-panel">
            <SectionHeading
              icon={Globe2}
              title="Infrastructure"
              description="Network and geographic context"
            />

            <div className="wb-detail-list">
              <DetailRow
                label="Observable"
                value={
                  observable.value
                  ?? query
                }
              />

              <DetailRow
                label="Type"
                value={
                  observable.type
                  ?? detectedType
                }
              />

              <DetailRow
                label="Country"
                value={country}
              />

              <DetailRow
                label="Country code"
                value={
                  enrichment.country_code
                }
              />

              <DetailRow
                label="Continent"
                value={continent}
              />

              <DetailRow
                label="ASN"
                value={asn}
              />

              <DetailRow
                label="Network"
                value={network}
              />

              <DetailRow
                label="AS domain"
                value={asDomain}
              />

              <DetailRow
                label="Enrichment provider"
                value={provider}
              />

              <DetailRow
                label="Enriched at"
                value={
                  formatDate(
                    enrichment.retrieved_at,
                  )
                }
              />

              <DetailRow
                label="First observed"
                value={
                  formatDate(
                    observable.first_seen,
                  )
                }
              />

              <DetailRow
                label="Last observed"
                value={
                  formatDate(
                    observable.last_seen,
                  )
                }
              />
            </div>
          </section>

          <MicrosoftContext
            detectedType={detectedType}
            query={
              observable.value
              ?? query
            }
          />
        </aside>
      </div>
    </>
  )
}


function GenericWorkbench({
  query,
  investigation,
}) {
  const vulnerability =
    investigation.vulnerability

  const technique =
    investigation.technique

  const indicator =
    investigation.indicators[0]

  let title = query
  let subtitle =
    'Local intelligence record'

  let icon = Binary
  let details = []
  let description = ''
  let reference = null


  if (vulnerability) {
    icon = ShieldAlert

    title =
      vulnerability.cve_id
      ?? query

    subtitle =
      vulnerability.name
      ?? 'Known exploited vulnerability'

    details = [
      [
        'Vendor',
        vulnerability.vendor,
      ],
      [
        'Product',
        vulnerability.product,
      ],
      [
        'Date added',
        vulnerability.date_added,
      ],
      [
        'Source',
        vulnerability.source,
      ],
    ]

    description =
      vulnerability.description
      ?? ''

    reference =
      vulnerability.source_reference
      ?? null
  } else if (technique) {
    icon = Swords

    title =
      technique.attack_id
      ?? query

    subtitle =
      technique.name
      ?? 'MITRE ATT&CK technique'

    details = [
      [
        'Technique type',
        technique.is_subtechnique
          ? 'Sub-technique'
          : 'Technique',
      ],
      [
        'Tactics',
        Array.isArray(
          technique.tactics,
        )
          ? technique.tactics.join(', ')
          : technique.tactics,
      ],
      [
        'Platforms',
        Array.isArray(
          technique.platforms,
        )
          ? technique.platforms.join(', ')
          : technique.platforms,
      ],
      [
        'Created',
        formatDate(
          technique.created,
        ),
      ],
      [
        'Modified',
        formatDate(
          technique.modified,
        ),
      ],
      [
        'Source',
        technique.source,
      ],
    ]

    description =
      technique.description
      ?? ''

    reference =
      technique.source_reference
      ?? null
  } else if (indicator) {
    icon = Radar

    title =
      indicator.value
      ?? query

    subtitle =
      'Threat indicator'

    details = [
      [
        'Source',
        indicator.source,
      ],
      [
        'Status',
        indicator.status,
      ],
      [
        'Threat type',
        indicator.threat_type,
      ],
      [
        'Malware family',
        indicator.malware_family,
      ],
      [
        'First observed',
        formatDate(
          indicator.first_seen,
        ),
      ],
      [
        'Last observed',
        formatDate(
          indicator.last_seen,
        ),
      ],
    ]

    reference =
      indicator.source_reference
      ?? null
  }


  const Icon = icon


  return (
    <>
      <section className="wb-object-header">
        <div className="wb-object-top">
          <div>
            <span className="wb-object-kind">
              <Icon size={13} />

              {investigation.detectedType}
            </span>

            <h2>{title}</h2>

            <p className="wb-object-subtitle">
              {subtitle}
            </p>
          </div>

          <span className="wb-local-match">
            Local intelligence match
          </span>
        </div>
      </section>

      <div className="wb-layout">
        <div className="wb-column">
          <section className="wb-panel">
            <SectionHeading
              icon={Database}
              title="Intelligence Context"
              description="Normalized local intelligence"
            />

            {description && (
              <p className="wb-summary-text">
                {description}
              </p>
            )}

            <div className="wb-detail-list">
              {details.map(
                ([label, value]) => (
                  <DetailRow
                    key={label}
                    label={label}
                    value={value}
                  />
                ),
              )}
            </div>

            {indicator?.tags?.length > 0 && (
              <div className="wb-tags">
                {indicator.tags.map(
                  (tag) => (
                    <span
                      className="wb-tag"
                      key={tag}
                    >
                      {tag}
                    </span>
                  ),
                )}
              </div>
            )}

            {reference && (
              <a
                className="wb-reference"
                href={reference}
                target="_blank"
                rel="noreferrer"
              >
                Source reference

                <ExternalLink size={13} />
              </a>
            )}
          </section>
        </div>

        <aside className="wb-column">
          <MicrosoftContext
            detectedType={
              investigation.detectedType
            }
            query={query}
          />
        </aside>
      </div>
    </>
  )
}


function Investigate({
  initialQuery = '',
}) {
  const [query, setQuery] =
    useState(initialQuery)

  const [
    submittedQuery,
    setSubmittedQuery,
  ] = useState('')

  const [
    investigation,
    setInvestigation,
  ] = useState(null)

  const [lookup, setLookup] =
    useState(null)

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState('')


  async function investigate(value) {
    const target =
      value.trim()

    if (!target) {
      return
    }

    setQuery(target)
    setSubmittedQuery(target)
    setLoading(true)
    setError('')
    setInvestigation(null)
    setLookup(null)

    try {
      const response =
        await fetch(
          `${API}/investigate?q=${
            encodeURIComponent(target)
          }&limit=25`,
        )

      if (!response.ok) {
        throw new Error(
          'The investigation request could not be completed.',
        )
      }

      const raw =
        await response.json()

      const normalized =
        normalizeInvestigation(raw)

      setInvestigation(normalized)

      if (
        normalized.found
        && (
          normalized.detectedType === 'ip'
          || normalized.detectedType === 'domain'
          || normalized.observables.length > 0
        )
      ) {
        try {
          const lookupResponse =
            await fetch(
              `${API}/observables/lookup?value=${
                encodeURIComponent(target)
              }&limit=25&offset=0`,
            )

          if (lookupResponse.ok) {
            const lookupData =
              await lookupResponse.json()

            setLookup(
              normalizeObservableLookup(
                lookupData,
              ),
            )
          }
        } catch {
          /*
           * The unified investigation remains usable
           * even if richer observable correlation
           * cannot be loaded.
           */
        }
      }
    } catch (requestError) {
      setError(
        requestError.message,
      )
    } finally {
      setLoading(false)
    }
  }


  useEffect(() => {
    if (initialQuery?.trim()) {
      investigate(initialQuery)
    }

    // Navigation-provided searches intentionally
    // rerun whenever initialQuery changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery])


  function submit(event) {
    event.preventDefault()

    investigate(query)
  }


  const isObservable =
    investigation
    && (
      investigation.detectedType === 'ip'
      || investigation.detectedType === 'domain'
      || investigation.observables.length > 0
    )


  return (
    <div className="workbench-page">
      <header className="page-header">
        <div>
          <span className="eyebrow">
            INTELLIGENCE WORKBENCH
          </span>

          <h1>
            Investigate
          </h1>

          <p>
            Pivot from an intelligence object into
            correlation, infrastructure, observations
            and security hunting context.
          </p>
        </div>

        <div className="header-symbol">
          <Fingerprint size={21} />
        </div>
      </header>

      <form
        className="wb-search"
        onSubmit={submit}
      >
        <Search size={19} />

        <input
          value={query}
          onChange={(event) => {
            setQuery(
              event.target.value,
            )
          }}
          placeholder="Investigate an IP, domain, URL, CVE, ATT&CK technique or hash..."
        />

        <button
          type="submit"
          disabled={loading}
        >
          {loading
            ? 'Investigating...'
            : 'Investigate'}
        </button>
      </form>

      <div className="wb-examples">
        {[
          '176.65.134.121',
          'drive.google.com',
          'CVE-2021-44228',
          'T1059',
        ].map((example) => (
          <button
            key={example}
            type="button"
            onClick={() => {
              investigate(example)
            }}
          >
            {example}
          </button>
        ))}
      </div>

      {error && (
        <div className="wb-state error">
          <strong>
            Investigation failed
          </strong>

          {error}
        </div>
      )}

      {loading && (
        <div className="wb-state">
          <strong>
            Correlating intelligence
          </strong>

          Searching normalized intelligence,
          observables and enrichment context...
        </div>
      )}

      {!loading
        && investigation
        && !investigation.found
        && (
          <div className="wb-state">
            <strong>
              No local intelligence match
            </strong>

            No record was found for{' '}
            <span className="mono">
              {submittedQuery}
            </span>
            .
          </div>
        )}

      {!loading
        && investigation?.found
        && (
          <div className="wb-shell">
            {isObservable ? (
              <ObservableWorkbench
                query={submittedQuery}
                investigation={
                  investigation
                }
                lookup={lookup}
              />
            ) : (
              <GenericWorkbench
                query={submittedQuery}
                investigation={
                  investigation
                }
              />
            )}
          </div>
        )}

      {!loading
        && !investigation
        && !error
        && (
          <div className="wb-state">
            <Activity size={24} />

            <strong>
              Start an intelligence investigation
            </strong>

            Search an observable, vulnerability or
            ATT&CK technique to build its local
            intelligence context.
          </div>
        )}
    </div>
  )
}


export default Investigate