import {
  Activity,
  ArrowRight,
  Bug,
  Database,
  ExternalLink,
  Fingerprint,
  Globe2,
  Network,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  Swords,
  Wifi,
} from 'lucide-react'
import {
  useEffect,
  useMemo,
  useState,
} from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import '../CommandCenter.css'


const API = '/api/v1'


function number(value) {
  return Number(value || 0)
}


function formatNumber(value) {
  return number(value).toLocaleString()
}


function formatDate(value) {
  if (!value) return '—'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return String(value)
  }

  return date.toLocaleString()
}


function getArray(object, ...keys) {
  for (const key of keys) {
    if (Array.isArray(object?.[key])) {
      return object[key]
    }
  }

  return []
}


function itemName(item) {
  return (
    item?.name
    ?? item?.value
    ?? item?.country
    ?? item?.asn
    ?? 'Unknown'
  )
}


function itemCount(item) {
  return number(
    item?.count
    ?? item?.total
    ?? item?.indicator_count,
  )
}


function KpiCard({
  icon: Icon,
  label,
  value,
  detail,
  tone = 'purple',
}) {
  return (
    <section className={`cc-kpi ${tone}`}>
      <div className="cc-kpi-icon">
        <Icon size={21} />
      </div>

      <div className="cc-kpi-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>

      <div className="cc-kpi-signal">
        <i />
        <i />
        <i />
        <i />
        <i />
        <i />
      </div>
    </section>
  )
}


function RankedList({
  items,
  emptyText,
  onSelect,
}) {
  const maximum =
    Math.max(
      ...items.map(itemCount),
      1,
    )

  if (!items.length) {
    return (
      <div className="cc-empty">
        {emptyText}
      </div>
    )
  }

  return (
    <div className="cc-ranking">
      {items.slice(0, 6).map(
        (item, index) => {
          const count = itemCount(item)
          const name = itemName(item)

          const content = (
            <>
              <span className="cc-rank">
                {index + 1}
              </span>

              <span
                className="cc-rank-name"
                title={name}
              >
                {name}
              </span>

              <span className="cc-rank-bar">
                <i
                  style={{
                    width:
                      `${Math.max(
                        (count / maximum) * 100,
                        4,
                      )}%`,
                  }}
                />
              </span>

              <strong>
                {formatNumber(count)}
              </strong>
            </>
          )

          if (onSelect) {
            return (
              <button
                className="cc-rank-row clickable"
                key={`${name}-${index}`}
                onClick={() => onSelect(name)}
                type="button"
              >
                {content}
              </button>
            )
          }

          return (
            <div
              className="cc-rank-row"
              key={`${name}-${index}`}
            >
              {content}
            </div>
          )
        },
      )}
    </div>
  )
}


function PanelHeader({
  icon: Icon,
  title,
  subtitle,
  action,
}) {
  return (
    <div className="cc-panel-header">
      <div className="cc-panel-title">
        {Icon && (
          <span>
            <Icon size={17} />
          </span>
        )}

        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>

      {action}
    </div>
  )
}


function Overview({
  onInvestigate,
}) {
  const [summary, setSummary] =
    useState(null)

  const [intelligence, setIntelligence] =
    useState(null)

  const [feed, setFeed] =
    useState([])

  const [query, setQuery] =
    useState('')

  const [loading, setLoading] =
    useState(true)

  const [error, setError] =
    useState('')


  useEffect(() => {
    const controller =
      new AbortController()

    async function load() {
      try {
        setLoading(true)
        setError('')

        const [
          summaryResponse,
          intelligenceResponse,
          feedResponse,
        ] = await Promise.all([
          fetch(
            `${API}/dashboard/summary`,
            {
              signal:
                controller.signal,
            },
          ),
          fetch(
            `${API}/dashboard/intelligence?limit=10`,
            {
              signal:
                controller.signal,
            },
          ),
          fetch(
            `${API}/feed?limit=8&offset=0`,
            {
              signal:
                controller.signal,
            },
          ),
        ])

        if (
          !summaryResponse.ok
          || !intelligenceResponse.ok
          || !feedResponse.ok
        ) {
          throw new Error(
            'Unable to load command center intelligence.',
          )
        }

        const [
          summaryPayload,
          intelligencePayload,
          feedPayload,
        ] = await Promise.all([
          summaryResponse.json(),
          intelligenceResponse.json(),
          feedResponse.json(),
        ])

        setSummary(summaryPayload)
        setIntelligence(
          intelligencePayload,
        )

        setFeed(
          feedPayload.items
          ?? feedPayload.feed
          ?? feedPayload.results
          ?? [],
        )
      } catch (loadError) {
        if (
          loadError.name
          !== 'AbortError'
        ) {
          setError(
            loadError.message,
          )
        }
      } finally {
        setLoading(false)
      }
    }

    load()

    return () => {
      controller.abort()
    }
  }, [])


  const indicators =
    number(
      summary?.indicators,
    )

  const online =
    number(
      summary?.online_indicators,
    )

  const vulnerabilities =
    number(
      summary?.vulnerabilities,
    )

  const observables =
    number(
      summary?.observables,
    )

  const ipObservables =
    number(
      summary?.ip_observables,
    )

  const domainObservables =
    number(
      summary?.domain_observables,
    )

  const techniques =
    number(
      summary
        ?.active_attack_techniques,
    )

  const offline =
    Math.max(
      indicators - online,
      0,
    )


  const activity = useMemo(
    () => getArray(
      intelligence,
      'recent_activity',
      'activity',
      'indicator_activity',
    ).map(
      (item) => ({
        date:
          item.date
          ?? item.day
          ?? item.name
          ?? '',
        count:
          number(
            item.count
            ?? item.total
            ?? item.indicators,
          ),
      }),
    ),
    [intelligence],
  )


  const topTags =
    getArray(
      intelligence,
      'top_tags',
      'tags',
    )

  const countries =
    getArray(
      intelligence,
      'top_countries',
      'countries',
    )

  const asns =
    getArray(
      intelligence,
      'top_asns',
      'asns',
    )

  const referenced =
    getArray(
      intelligence,
      'most_referenced_observables',
      'top_observables',
      'observables',
    )


  function investigate() {
    const value =
      query.trim()

    if (!value) return

    onInvestigate(value)
  }


  function handleSubmit(event) {
    event.preventDefault()
    investigate()
  }


  const onlinePercent =
    indicators > 0
      ? (
          online
          / indicators
        ) * 100
      : 0

  const offlinePercent =
    indicators > 0
      ? (
          offline
          / indicators
        ) * 100
      : 0


  return (
    <div className="command-center">
      <section className="cc-hero">
        <div className="cc-hero-grid" />

        <div className="cc-globe">
          <div className="cc-globe-ring ring-one" />
          <div className="cc-globe-ring ring-two" />
          <div className="cc-globe-ring ring-three" />

          <span className="node n1" />
          <span className="node n2" />
          <span className="node n3" />
          <span className="node n4" />
          <span className="node n5" />
        </div>

        <div className="cc-hero-copy">
          <span className="cc-eyebrow">
            THREAT INTELLIGENCE OPERATIONS
          </span>

          <h1>
            Command
            {' '}
            <strong>Center</strong>
          </h1>

          <p>
            Real-time visibility across collected,
            normalized, correlated and enriched
            cyber threat intelligence.
          </p>
        </div>

        <div className="cc-platform-status">
          <span className="cc-status-label">
            PLATFORM STATUS
          </span>

          <div className="cc-status-grid">
            <div>
              <strong className="operational">
                <i />
                Operational
              </strong>

              <small>
                Intelligence services available
              </small>
            </div>

            <div>
              <strong>4</strong>
              <small>Sources</small>
            </div>

            <div>
              <strong>
                {formatNumber(indicators)}
              </strong>
              <small>Total indicators</small>
            </div>
          </div>

          <div className="cc-status-footer">
            <span>
              {loading
                ? 'Refreshing intelligence…'
                : 'Current local dataset'}
            </span>

            <strong>
              <i />
              LIVE DATA
            </strong>
          </div>
        </div>
      </section>

      {error && (
        <div className="cc-error">
          <ShieldAlert size={17} />
          {error}
        </div>
      )}

      <form
        className="cc-search"
        onSubmit={handleSubmit}
      >
        <Search size={19} />

        <input
          value={query}
          onChange={(event) => (
            setQuery(
              event.target.value,
            )
          )}
          placeholder="Investigate IP, domain, URL, CVE or ATT&CK technique..."
        />

        <button type="submit">
          Investigate
          <ArrowRight size={15} />
        </button>
      </form>

      <div className="cc-kpi-grid">
        <KpiCard
          icon={Fingerprint}
          label="TOTAL INDICATORS"
          value={
            loading
              ? '—'
              : formatNumber(
                  indicators,
                )
          }
          detail={
            `${formatNumber(
              online,
            )} currently online`
          }
        />

        <KpiCard
          icon={ShieldCheck}
          label="KNOWN EXPLOITED"
          value={
            loading
              ? '—'
              : formatNumber(
                  vulnerabilities,
                )
          }
          detail="CISA KEV catalog"
          tone="red"
        />

        <KpiCard
          icon={Network}
          label="OBSERVABLES"
          value={
            loading
              ? '—'
              : formatNumber(
                  observables,
                )
          }
          detail={
            `${formatNumber(
              ipObservables,
            )} IP · ${formatNumber(
              domainObservables,
            )} domain`
          }
          tone="green"
        />

        <KpiCard
          icon={Swords}
          label="ATT&CK TECHNIQUES"
          value={
            loading
              ? '—'
              : formatNumber(
                  techniques,
                )
          }
          detail="Active Enterprise knowledge"
          tone="amber"
        />
      </div>

      <div className="cc-main-grid">
        <section className="cc-panel cc-activity-panel">
          <PanelHeader
            icon={Activity}
            title="Intelligence Activity"
            subtitle="Indicators first observed during the recent collection window"
            action={
              <span className="cc-panel-chip">
                Recent activity
              </span>
            }
          />

          <div className="cc-chart">
            {activity.length > 0 ? (
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <AreaChart
                  data={activity}
                  margin={{
                    top: 10,
                    right: 10,
                    left: -15,
                    bottom: 0,
                  }}
                >
                  <defs>
                    <linearGradient
                      id="activityFill"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >
                      <stop
                        offset="0%"
                        stopColor="#9b6cff"
                        stopOpacity={0.42}
                      />

                      <stop
                        offset="100%"
                        stopColor="#9b6cff"
                        stopOpacity={0.015}
                      />
                    </linearGradient>
                  </defs>

                  <CartesianGrid
                    stroke="rgba(145, 126, 175, .14)"
                    strokeDasharray="4 4"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="date"
                    tick={{
                      fill: '#8c8799',
                      fontSize: 10,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    tick={{
                      fill: '#8c8799',
                      fontSize: 10,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={{
                      background:
                        '#15131d',
                      border:
                        '1px solid #342e47',
                      borderRadius: 8,
                      fontSize: 11,
                    }}
                  />

                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#9b6cff"
                    strokeWidth={2}
                    fill="url(#activityFill)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="cc-empty">
                Activity data is not available.
              </div>
            )}
          </div>
        </section>

        <section className="cc-panel">
          <PanelHeader
            icon={Network}
            title="Observable Composition"
            subtitle="Normalized infrastructure objects"
          />

          <div className="cc-composition">
            <div className="cc-donut">
              <div className="cc-donut-center">
                <strong>
                  {formatNumber(
                    observables,
                  )}
                </strong>
                <span>Total</span>
              </div>
            </div>

            <div className="cc-composition-list">
              <div>
                <span>
                  <i className="ip" />
                  IP addresses
                </span>

                <strong>
                  {formatNumber(
                    ipObservables,
                  )}
                </strong>
              </div>

              <div>
                <span>
                  <i className="domain" />
                  Domains
                </span>

                <strong>
                  {formatNumber(
                    domainObservables,
                  )}
                </strong>
              </div>

              <div>
                <span>
                  <i className="enriched" />
                  Enriched IPs
                </span>

                <strong>
                  {formatNumber(
                    summary?.enriched_ips,
                  )}
                </strong>
              </div>
            </div>
          </div>
        </section>

        <section className="cc-panel">
          <PanelHeader
            icon={Wifi}
            title="Indicator State"
            subtitle="Current URLhaus record status"
          />

          <div className="cc-state-list">
            <div>
              <div className="cc-state-label">
                <span>Online</span>
                <strong>
                  {formatNumber(
                    online,
                  )}
                </strong>
              </div>

              <div className="cc-state-track">
                <i
                  className="online"
                  style={{
                    width:
                      `${onlinePercent}%`,
                  }}
                />
              </div>

              <small>
                {onlinePercent.toFixed(1)}%
              </small>
            </div>

            <div>
              <div className="cc-state-label">
                <span>Offline</span>
                <strong>
                  {formatNumber(
                    offline,
                  )}
                </strong>
              </div>

              <div className="cc-state-track">
                <i
                  className="offline"
                  style={{
                    width:
                      `${offlinePercent}%`,
                  }}
                />
              </div>

              <small>
                {offlinePercent.toFixed(1)}%
              </small>
            </div>
          </div>
        </section>
      </div>

      <div className="cc-lower-grid">
        <section className="cc-panel">
          <PanelHeader
            icon={Bug}
            title="Top Intelligence Tags"
            subtitle="Most prevalent context in collected indicators"
          />

          <RankedList
            items={topTags}
            emptyText="No tag intelligence available."
          />
        </section>

        <section className="cc-panel">
          <PanelHeader
            icon={Globe2}
            title="Observed Infrastructure"
            subtitle="Countries associated with enriched IP observables"
          />

          <RankedList
            items={countries}
            emptyText="No geographic enrichment available."
          />

          <p className="cc-context-note">
            Geographic data describes observed
            infrastructure location and does not
            imply that a country or network is
            malicious.
          </p>
        </section>

        <section className="cc-panel cc-recent-panel">
          <PanelHeader
            icon={Radar}
            title="Recent Intelligence"
            subtitle="Latest records entering the platform"
            action={
              <span className="cc-panel-chip">
                LIVE
              </span>
            }
          />

          <div className="cc-feed">
            {feed.length > 0 ? (
              feed.slice(0, 6).map(
                (item, index) => {
                  const value =
                    item.value
                    ?? item.cve_id
                    ?? item.title
                    ?? item.name
                    ?? 'Intelligence record'

                  return (
                    <button
                      className="cc-feed-row"
                      key={
                        item.id
                        ?? `${value}-${index}`
                      }
                      onClick={() => (
                        onInvestigate(
                          value,
                        )
                      )}
                      type="button"
                    >
                      <span className="cc-feed-type">
                        {
                          item.feed_type
                          ?? item.type
                          ?? item.source
                          ?? 'intel'
                        }
                      </span>

                      <span className="cc-feed-value">
                        <strong>
                          {value}
                        </strong>

                        <small>
                          {
                            item.threat_type
                            ?? item.vendor
                            ?? item.source
                            ?? 'intelligence'
                          }
                        </small>
                      </span>

                      <span className="cc-feed-time">
                        {formatDate(
                          item.last_seen
                          ?? item.first_seen
                          ?? item.date_added
                          ?? item.timestamp,
                        )}
                      </span>

                      <ExternalLink
                        size={13}
                      />
                    </button>
                  )
                },
              )
            ) : (
              <div className="cc-empty">
                No recent intelligence records.
              </div>
            )}
          </div>
        </section>
      </div>

      <div className="cc-insight-grid">
        <section className="cc-panel">
          <PanelHeader
            icon={Database}
            title="Most Referenced Observables"
            subtitle="Infrastructure with the highest local relationship counts"
          />

          <RankedList
            items={referenced}
            emptyText="No relationship intelligence available."
            onSelect={onInvestigate}
          />
        </section>

        <section className="cc-panel">
          <PanelHeader
            icon={Network}
            title="Network Context"
            subtitle="Most represented autonomous systems in enriched observables"
          />

          <RankedList
            items={asns}
            emptyText="No ASN enrichment available."
          />

          <p className="cc-context-note">
            ASN frequency represents infrastructure
            observed in the current dataset, not a
            reputation or maliciousness score.
          </p>
        </section>
      </div>
    </div>
  )
}


export default Overview