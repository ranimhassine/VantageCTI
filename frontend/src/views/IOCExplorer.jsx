import {
  Binary,
  ExternalLink,
  Filter,
  Radar,
  Search,
} from 'lucide-react'
import { useEffect, useState } from 'react'

import Pagination from '../components/Pagination'


const API = '/api/v1'
const LIMIT = 25


function IOCExplorer({ onInvestigate }) {
  const [data, setData] = useState(null)
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [tag, setTag] = useState('')
  const [family, setFamily] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      try {
        setLoading(true)
        setError('')

        const params = new URLSearchParams({
          limit: String(LIMIT),
          offset: String(offset),
        })

        if (status) params.set('status', status)
        if (tag) params.set('tag', tag)
        if (family) params.set('malware_family', family)

        const response = await fetch(
          `${API}/indicators?${params}`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error('Unable to load indicators.')
        }

        const payload = await response.json()

        const items =
          payload.indicators
          || payload.items
          || []

        const filtered = search.trim()
          ? items.filter((item) => {
              const needle = search.toLowerCase()

              return [
                item.value,
                item.type,
                item.status,
                item.threat_type,
                item.malware_family,
                item.source,
                ...(item.tags || []),
              ]
                .filter(Boolean)
                .join(' ')
                .toLowerCase()
                .includes(needle)
            })
          : items

        setData({
          ...payload,
          indicators: filtered,
        })
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setError(loadError.message)
        }
      } finally {
        setLoading(false)
      }
    }

    const timer = setTimeout(load, 200)

    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [offset, status, tag, family, search])

  function update(setter, value) {
    setOffset(0)
    setter(value)
  }

  const indicators = data?.indicators || []

  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">
            INDICATOR INTELLIGENCE
          </span>

          <h1>IOC Explorer</h1>

          <p>
            Search, filter and pivot across normalized
            indicators collected by the platform.
          </p>
        </div>

        <div className="header-symbol">
          <Radar size={20} />
        </div>
      </header>

      <section className="intel-hero-strip">
        <div>
          <span>DATASET</span>
          <strong>
            {data?.total?.toLocaleString() ?? '—'}
          </strong>
          <small>stored indicators</small>
        </div>

        <div>
          <span>COLLECTION</span>
          <strong>URLhaus</strong>
          <small>indicator intelligence</small>
        </div>

        <div>
          <span>PRIMARY TYPE</span>
          <strong>URL</strong>
          <small>normalized IOC records</small>
        </div>

        <div>
          <span>WORKFLOW</span>
          <strong>Pivot</strong>
          <small>open in investigation</small>
        </div>
      </section>

      <section className="toolbar intel-toolbar">
        <label className="toolbar-search">
          <Search size={16} />

          <input
            value={search}
            onChange={(event) => {
              update(setSearch, event.target.value)
            }}
            placeholder="Search loaded IOC values, tags, family..."
          />
        </label>

        <div className="filters">
          <Filter size={15} />

          <select
            value={status}
            onChange={(event) => {
              update(setStatus, event.target.value)
            }}
          >
            <option value="">All states</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>

          <input
            className="filter-input"
            value={tag}
            onChange={(event) => {
              update(setTag, event.target.value)
            }}
            placeholder="Tag"
          />

          <input
            className="filter-input"
            value={family}
            onChange={(event) => {
              update(setFamily, event.target.value)
            }}
            placeholder="Family"
          />
        </div>
      </section>

      <section className="panel browser-panel">
        <div className="browser-summary intel-browser-heading">
          <div>
            <strong>
              {data?.total?.toLocaleString() ?? '—'}
            </strong>
            <span>matching indicators</span>
          </div>

          <span className="intel-context-label">
            Click an IOC to investigate
          </span>
        </div>

        {error && (
          <div className="page-state error-state">
            {error}
          </div>
        )}

        {loading && (
          <div className="page-state">
            Loading indicator intelligence...
          </div>
        )}

        {!loading && data && (
          <>
            {indicators.length === 0 ? (
              <div className="page-state">
                No indicators match the current filters.
              </div>
            ) : (
              <div className="ioc-table">
                <div className="ioc-row ioc-header">
                  <span>State</span>
                  <span>Indicator</span>
                  <span>Threat</span>
                  <span>Family / Tags</span>
                  <span>Source</span>
                  <span />
                </div>

                {indicators.map((indicator) => (
                  <div
                    className="ioc-row"
                    key={indicator.id}
                  >
                    <span>
                      <span
                        className={
                          `status-badge ${indicator.status || ''}`
                        }
                      >
                        {indicator.status || 'unknown'}
                      </span>
                    </span>

                    <button
                      className="ioc-value"
                      onClick={() => {
                        onInvestigate(indicator.value)
                      }}
                    >
                      <Binary size={14} />

                      <span>
                        <strong>
                          {indicator.type || 'indicator'}
                        </strong>

                        <code>{indicator.value}</code>
                      </span>
                    </button>

                    <span className="ioc-secondary">
                      {indicator.threat_type || '—'}
                    </span>

                    <div className="ioc-tags-cell">
                      {indicator.malware_family && (
                        <strong>
                          {indicator.malware_family}
                        </strong>
                      )}

                      <div className="compact-tags">
                        {(indicator.tags || [])
                          .slice(0, 4)
                          .map((item) => (
                            <span key={item}>
                              {item}
                            </span>
                          ))}
                      </div>
                    </div>

                    <span className="source-badge">
                      {indicator.source}
                    </span>

                    <span>
                      {indicator.source_reference && (
                        <a
                          className="icon-link"
                          href={indicator.source_reference}
                          target="_blank"
                          rel="noreferrer"
                          title="Open source record"
                        >
                          <ExternalLink size={15} />
                        </a>
                      )}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <Pagination
              total={data.total || indicators.length}
              limit={LIMIT}
              offset={offset}
              onChange={setOffset}
            />
          </>
        )}
      </section>
    </>
  )
}


export default IOCExplorer