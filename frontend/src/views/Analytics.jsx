import {
  Activity,
  BarChart3,
  Globe2,
  Network,
  Radar,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'


const API = '/api/v1'


function formatNumber(value) {
  if (value === null || value === undefined) {
    return '—'
  }

  return Number(value).toLocaleString()
}


function Analytics({ onInvestigate }) {
  const [summary, setSummary] = useState(null)
  const [intelligence, setIntelligence] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      try {
        setLoading(true)
        setError('')

        const [summaryResponse, intelligenceResponse] =
          await Promise.all([
            fetch(
              `${API}/dashboard/summary`,
              { signal: controller.signal },
            ),
            fetch(
              `${API}/dashboard/intelligence?limit=10`,
              { signal: controller.signal },
            ),
          ])

        if (
          !summaryResponse.ok
          || !intelligenceResponse.ok
        ) {
          throw new Error(
            'Unable to load intelligence analytics.',
          )
        }

        setSummary(await summaryResponse.json())
        setIntelligence(
          await intelligenceResponse.json(),
        )
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setError(loadError.message)
        }
      } finally {
        setLoading(false)
      }
    }

    load()

    return () => controller.abort()
  }, [])

  const activity = useMemo(() => {
    return (
      intelligence?.recent_activity
      || intelligence?.activity
      || []
    )
  }, [intelligence])

  const countries = useMemo(() => {
    return (
      intelligence?.top_countries
      || intelligence?.countries
      || []
    )
  }, [intelligence])

  const asns = useMemo(() => {
    return (
      intelligence?.top_asns
      || intelligence?.asns
      || []
    )
  }, [intelligence])

  const tags = useMemo(() => {
    return (
      intelligence?.top_tags
      || intelligence?.tags
      || []
    )
  }, [intelligence])

  const observables = useMemo(() => {
    return (
      intelligence?.most_referenced_observables
      || intelligence?.top_observables
      || []
    )
  }, [intelligence])

  const statusData = [
    {
      name: 'Online',
      count: summary?.online_indicators || 0,
    },
    {
      name: 'Offline',
      count: Math.max(
        (summary?.indicators || 0)
        - (summary?.online_indicators || 0),
        0,
      ),
    },
  ]

  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">
            INTELLIGENCE ANALYTICS
          </span>

          <h1>Analytics</h1>

          <p>
            Operational trends and distributions across
            the platform's normalized intelligence.
          </p>
        </div>

        <div className="header-symbol">
          <BarChart3 size={20} />
        </div>
      </header>

      {error && (
        <div className="page-state error-state">
          {error}
        </div>
      )}

      {loading && (
        <div className="page-state">
          Building intelligence analytics...
        </div>
      )}

      {!loading && summary && intelligence && (
        <>
          <section className="analytics-kpis">
            <AnalyticsKpi
              icon={Radar}
              label="Indicators"
              value={formatNumber(summary.indicators)}
              detail={
                `${formatNumber(
                  summary.online_indicators,
                )} currently online`
              }
            />

            <AnalyticsKpi
              icon={Globe2}
              label="Observables"
              value={formatNumber(summary.observables)}
              detail={
                `${formatNumber(
                  summary.ip_observables,
                )} IP · ${formatNumber(
                  summary.domain_observables,
                )} domains`
              }
            />

            <AnalyticsKpi
              icon={Network}
              label="Enriched IPs"
              value={formatNumber(summary.enriched_ips)}
              detail="Infrastructure context available"
            />

            <AnalyticsKpi
              icon={Activity}
              label="ATT&CK"
              value={formatNumber(
                summary.active_attack_techniques,
              )}
              detail="Active techniques indexed"
            />
          </section>

          <section className="analytics-grid">
            <div className="panel analytics-wide">
              <div className="panel-heading">
                <h2>Collection activity</h2>
                <p>
                  Intelligence records observed over
                  recent collection dates.
                </p>
              </div>

              <div className="analytics-chart">
                <ResponsiveContainer
                  width="100%"
                  height="100%"
                >
                  <AreaChart data={activity}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      vertical={false}
                      stroke="#24212f"
                    />

                    <XAxis
                      dataKey="date"
                      tick={{
                        fill: '#777181',
                        fontSize: 9,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      tick={{
                        fill: '#777181',
                        fontSize: 9,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={{
                        background: '#111017',
                        border: '1px solid #342e47',
                        borderRadius: 8,
                        fontSize: 10,
                      }}
                    />

                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#9b6cff"
                      fill="#9b6cff"
                      fillOpacity={0.12}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="panel">
              <div className="panel-heading">
                <h2>Indicator state</h2>
                <p>
                  Current URLhaus lifecycle state.
                </p>
              </div>

              <div className="analytics-chart compact">
                <ResponsiveContainer
                  width="100%"
                  height="100%"
                >
                  <BarChart data={statusData}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      vertical={false}
                      stroke="#24212f"
                    />

                    <XAxis
                      dataKey="name"
                      tick={{
                        fill: '#777181',
                        fontSize: 9,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      tick={{
                        fill: '#777181',
                        fontSize: 9,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={{
                        background: '#111017',
                        border: '1px solid #342e47',
                        borderRadius: 8,
                        fontSize: 10,
                      }}
                    />

                    <Bar
                      dataKey="count"
                      fill="#9b6cff"
                      radius={[4, 4, 0, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="panel">
              <div className="panel-heading">
                <h2>Infrastructure countries</h2>
                <p>
                  Geographic metadata associated with
                  observed IP infrastructure.
                </p>
              </div>

              <AnalyticsRanking
                items={countries}
              />
            </div>

            <div className="panel">
              <div className="panel-heading">
                <h2>Autonomous systems</h2>
                <p>
                  Networks most represented in enriched
                  IP observables.
                </p>
              </div>

              <AnalyticsRanking
                items={asns}
              />
            </div>

            <div className="panel">
              <div className="panel-heading">
                <h2>Observed tags</h2>
                <p>
                  Most common source-provided
                  intelligence classifications.
                </p>
              </div>

              <div className="analytics-tags">
                {tags.map((tag, index) => (
                  <div
                    key={`${tag.name || tag.tag}-${index}`}
                  >
                    <span>
                      {tag.name || tag.tag}
                    </span>

                    <strong>
                      {formatNumber(
                        tag.count ?? tag.value,
                      )}
                    </strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel analytics-wide">
              <div className="panel-heading">
                <h2>Most referenced observables</h2>
                <p>
                  Infrastructure with the highest number
                  of relationships in the local dataset.
                </p>
              </div>

              <div className="analytics-observables">
                {observables.map((observable, index) => {
                  const value =
                    observable.value
                    || observable.observable
                    || observable.name

                  const count =
                    observable.count
                    || observable.related_indicator_count
                    || observable.relationships
                    || 0

                  return (
                    <button
                      key={`${value}-${index}`}
                      onClick={() => {
                        if (value) {
                          onInvestigate(value)
                        }
                      }}
                    >
                      <span className="rank">
                        {String(index + 1)
                          .padStart(2, '0')}
                      </span>

                      <code>{value}</code>

                      <strong>
                        {formatNumber(count)}
                      </strong>

                      <small>relationships</small>
                    </button>
                  )
                })}
              </div>
            </div>
          </section>

          <div className="information-banner analytics-note">
            <Globe2 size={17} />

            <p>
              Country and autonomous-system distributions
              describe infrastructure observed in the
              intelligence dataset. They must not be
              interpreted as country, provider or network
              maliciousness scores.
            </p>
          </div>
        </>
      )}
    </>
  )
}


function AnalyticsKpi({
  icon: Icon,
  label,
  value,
  detail,
}) {
  return (
    <div className="analytics-kpi">
      <div className="analytics-kpi-icon">
        <Icon size={17} />
      </div>

      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </div>
  )
}


function AnalyticsRanking({ items }) {
  if (!items.length) {
    return (
      <div className="analytics-empty">
        No distribution data available.
      </div>
    )
  }

  const maximum = Math.max(
    ...items.map(
      (item) => Number(item.count ?? item.value ?? 0),
    ),
    1,
  )

  return (
    <div className="analytics-ranking">
      {items.map((item, index) => {
        const name =
          item.name
          || item.country
          || item.asn
          || 'Unknown'

        const secondary =
          item.as_name
          || item.country_code
          || ''

        const count =
          Number(item.count ?? item.value ?? 0)

        return (
          <div
            className="analytics-rank-row"
            key={`${name}-${index}`}
          >
            <span className="rank">
              {String(index + 1).padStart(2, '0')}
            </span>

            <div>
              <strong>{name}</strong>

              {secondary && (
                <small>{secondary}</small>
              )}

              <div className="analytics-bar">
                <span
                  style={{
                    width:
                      `${Math.max(
                        (count / maximum) * 100,
                        2,
                      )}%`,
                  }}
                />
              </div>
            </div>

            <strong>
              {formatNumber(count)}
            </strong>
          </div>
        )
      })}
    </div>
  )
}


export default Analytics