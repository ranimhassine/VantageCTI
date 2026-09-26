import {
  CalendarDays,
  Search,
  ShieldAlert,
} from 'lucide-react'
import { useEffect, useState } from 'react'


const API = '/api/v1'
const LIMIT = 100


function Vulnerabilities({ onInvestigate }) {
  const [records, setRecords] = useState([])
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')


  useEffect(() => {
    async function load() {
      try {
        setLoading(true)

        const response = await fetch(
          `${API}/vulnerabilities?limit=${LIMIT}`,
        )

        if (!response.ok) {
          throw new Error(
            'Unable to load vulnerability intelligence.',
          )
        }

        const data = await response.json()

        setRecords(
          Array.isArray(data)
            ? data
            : data.vulnerabilities
              ?? data.items
              ?? [],
        )
      } catch (loadError) {
        setError(loadError.message)
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [])


  const normalizedQuery = query
    .trim()
    .toLowerCase()

  const filtered = records.filter((item) => {
    if (!normalizedQuery) {
      return true
    }

    return [
      item.cve_id,
      item.vendor,
      item.product,
      item.name,
      item.description,
    ]
      .filter(Boolean)
      .some((value) => (
        String(value)
          .toLowerCase()
          .includes(normalizedQuery)
      ))
  })


  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">
            EXPLOITED VULNERABILITY INTELLIGENCE
          </span>

          <h1>Vulnerabilities</h1>

          <p>
            Browse known exploited vulnerabilities
            collected from CISA KEV.
          </p>
        </div>

        <div className="header-symbol">
          <ShieldAlert size={21} />
        </div>
      </header>

      <section className="vulnerability-summary">
        <div className="mini-stat">
          <span>Loaded records</span>
          <strong>
            {records.length.toLocaleString()}
          </strong>
        </div>

        <div className="mini-stat">
          <span>Source</span>
          <strong>CISA KEV</strong>
        </div>

        <div className="mini-stat">
          <span>Intelligence type</span>
          <strong>Known exploited</strong>
        </div>
      </section>

      <section className="toolbar">
        <label className="toolbar-search">
          <Search size={16} />

          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value)
            }}
            placeholder="Search CVE, vendor, product or vulnerability..."
          />
        </label>
      </section>

      <section className="panel browser-panel">
        <div className="browser-summary">
          <div>
            <strong>
              {filtered.length.toLocaleString()}
            </strong>
            <span>matching loaded vulnerabilities</span>
          </div>
        </div>

        {error && (
          <div className="page-state error-state">
            {error}
          </div>
        )}

        {loading && (
          <div className="page-state">
            Loading vulnerability intelligence...
          </div>
        )}

        {!loading && !error && (
          <div className="vulnerability-list">
            {filtered.map((item) => (
              <button
                className="vulnerability-record"
                key={item.cve_id}
                onClick={() => {
                  onInvestigate(item.cve_id)
                }}
              >
                <div className="vulnerability-id">
                  <ShieldAlert size={16} />
                  <strong>{item.cve_id}</strong>
                </div>

                <div className="vulnerability-main">
                  <div className="record-meta">
                    <span className="source-badge">
                      {item.vendor || 'Unknown vendor'}
                    </span>

                    {item.product && (
                      <span className="type-pill">
                        {item.product}
                      </span>
                    )}
                  </div>

                  <h3>
                    {item.name || item.cve_id}
                  </h3>

                  <p>
                    {item.description
                      || 'No description available.'}
                  </p>
                </div>

                <div className="vulnerability-date">
                  <CalendarDays size={14} />
                  <span>
                    {item.date_added || 'Unknown'}
                  </span>
                </div>
              </button>
            ))}

            {!filtered.length && (
              <div className="page-state">
                No matching vulnerabilities.
              </div>
            )}
          </div>
        )}
      </section>
    </>
  )
}


export default Vulnerabilities