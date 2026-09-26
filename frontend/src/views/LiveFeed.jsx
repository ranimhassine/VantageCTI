import {
  Binary,
  ExternalLink,
  Filter,
  Search,
  ShieldAlert,
} from 'lucide-react'
import { useEffect, useState } from 'react'

import Pagination from '../components/Pagination'


const API = '/api/v1'
const LIMIT = 25


function LiveFeed({ onInvestigate }) {
  const [data, setData] = useState(null)
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [source, setSource] = useState('')
  const [type, setType] = useState('')
  const [status, setStatus] = useState('')
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

        if (search) params.set('search', search)
        if (source) params.set('source', source)
        if (type) params.set('feed_type', type)
        if (status) params.set('status', status)

        const response = await fetch(
          `${API}/feed?${params}`,
          {
            signal: controller.signal,
          },
        )

        if (!response.ok) {
          throw new Error(
            'Unable to load intelligence feed.',
          )
        }

        setData(await response.json())
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setError(loadError.message)
        }
      } finally {
        setLoading(false)
      }
    }

    const timer = setTimeout(load, 250)

    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [offset, search, source, type, status])


  function resetOffset(setter, value) {
    setOffset(0)
    setter(value)
  }


  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">
            NORMALIZED INTELLIGENCE
          </span>

          <h1>Live Feed</h1>

          <p>
            Chronological intelligence from active
            collection sources.
          </p>
        </div>
      </header>

      <section className="toolbar">
        <label className="toolbar-search">
          <Search size={16} />

          <input
            value={search}
            onChange={(event) => {
              resetOffset(
                setSearch,
                event.target.value,
              )
            }}
            placeholder="Search CVE, URL, title or source ID..."
          />
        </label>

        <div className="filters">
          <Filter size={15} />

          <select
            value={source}
            onChange={(event) => {
              resetOffset(
                setSource,
                event.target.value,
              )
            }}
          >
            <option value="">All sources</option>
            <option value="URLhaus">URLhaus</option>
            <option value="CISA KEV">CISA KEV</option>
          </select>

          <select
            value={type}
            onChange={(event) => {
              resetOffset(
                setType,
                event.target.value,
              )
            }}
          >
            <option value="">All types</option>
            <option value="indicator">
              Indicators
            </option>
            <option value="vulnerability">
              Vulnerabilities
            </option>
          </select>

          <select
            value={status}
            onChange={(event) => {
              resetOffset(
                setStatus,
                event.target.value,
              )
            }}
          >
            <option value="">All states</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
        </div>
      </section>

      <section className="panel browser-panel">
        <div className="browser-summary">
          <div>
            <strong>
              {data?.total?.toLocaleString() ?? '—'}
            </strong>
            <span>matching intelligence records</span>
          </div>
        </div>

        {error && (
          <div className="page-state error-state">
            {error}
          </div>
        )}

        {loading && (
          <div className="page-state">
            Loading feed...
          </div>
        )}

        {!loading && data && (
          <>
            <div className="records">
              {data.items.map((item, index) => (
                <article
                  className="record"
                  key={`${item.source}-${item.source_id}-${index}`}
                >
                  <div
                    className={`record-icon ${item.type}`}
                  >
                    {item.type === 'vulnerability'
                      ? <ShieldAlert size={18} />
                      : <Binary size={18} />}
                  </div>

                  <button
                    className="record-main"
                    onClick={() => {
                      onInvestigate(item.observable)
                    }}
                  >
                    <div className="record-meta">
                      <span className="source-badge">
                        {item.source}
                      </span>

                      <span className="type-pill">
                        {item.type}
                      </span>

                      {item.status && (
                        <span
                          className={`status-badge ${item.status}`}
                        >
                          {item.status}
                        </span>
                      )}
                    </div>

                    <h3>{item.title}</h3>

                    <p className="mono">
                      {item.observable}
                    </p>

                    {item.summary && (
                      <p className="record-description">
                        {item.summary}
                      </p>
                    )}
                  </button>

                  {item.source_reference && (
                    <a
                      className="icon-link"
                      href={item.source_reference}
                      target="_blank"
                      rel="noreferrer"
                    >
                      <ExternalLink size={16} />
                    </a>
                  )}
                </article>
              ))}
            </div>

            <Pagination
              total={data.total}
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


export default LiveFeed