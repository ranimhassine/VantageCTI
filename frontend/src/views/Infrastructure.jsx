import {
  Globe2,
  Search,
  Server,
} from 'lucide-react'
import { useEffect, useState } from 'react'

import Pagination from '../components/Pagination'


const API = '/api/v1'
const LIMIT = 25


function Infrastructure({ onInvestigate }) {
  const [data, setData] = useState(null)
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [type, setType] = useState('')
  const [country, setCountry] = useState('')
  const [asn, setAsn] = useState('')
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
        if (type) params.set('observable_type', type)
        if (country) params.set('country', country)
        if (asn) params.set('asn', asn)

        const response = await fetch(
          `${API}/observables?${params}`,
          {
            signal: controller.signal,
          },
        )

        if (!response.ok) {
          throw new Error(
            'Unable to load infrastructure.',
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
  }, [
    offset,
    search,
    type,
    country,
    asn,
  ])


  function update(setter, value) {
    setOffset(0)
    setter(value)
  }


  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">
            CORRELATED OBSERVABLES
          </span>

          <h1>Infrastructure</h1>

          <p>
            Explore infrastructure extracted from
            collected threat-intelligence records.
          </p>
        </div>
      </header>

      <section className="toolbar infrastructure-toolbar">
        <label className="toolbar-search">
          <Search size={16} />

          <input
            value={search}
            onChange={(event) => {
              update(
                setSearch,
                event.target.value,
              )
            }}
            placeholder="Search IP or domain..."
          />
        </label>

        <div className="filters">
          <select
            value={type}
            onChange={(event) => {
              update(setType, event.target.value)
            }}
          >
            <option value="">IP + domain</option>
            <option value="ip">IP addresses</option>
            <option value="domain">Domains</option>
          </select>

          <input
            className="filter-input"
            value={country}
            onChange={(event) => {
              update(
                setCountry,
                event.target.value,
              )
            }}
            placeholder="Country"
          />

          <input
            className="filter-input"
            value={asn}
            onChange={(event) => {
              update(
                setAsn,
                event.target.value,
              )
            }}
            placeholder="ASN"
          />
        </div>
      </section>

      <div className="information-banner">
        <Globe2 size={17} />

        <p>
          Geographic and ASN information describes
          infrastructure associated with observed IP
          addresses. It is contextual metadata, not a
          maliciousness score.
        </p>
      </div>

      <section className="panel browser-panel">
        <div className="browser-summary">
          <div>
            <strong>
              {data?.total?.toLocaleString() ?? '—'}
            </strong>
            <span>matching observables</span>
          </div>
        </div>

        {error && (
          <div className="page-state error-state">
            {error}
          </div>
        )}

        {loading && (
          <div className="page-state">
            Loading infrastructure...
          </div>
        )}

        {!loading && data && (
          <>
            <div className="table">
              <div className="table-header infrastructure-columns">
                <span>Type</span>
                <span>Observable</span>
                <span>Country</span>
                <span>ASN / Network</span>
                <span>Relationships</span>
              </div>

              {data.observables.map(
                (observable) => (
                  <button
                    className="table-record infrastructure-columns"
                    key={observable.id}
                    onClick={() => {
                      onInvestigate(
                        observable.value,
                      )
                    }}
                  >
                    <span>
                      <span className="type-pill">
                        {observable.type}
                      </span>
                    </span>

                    <span className="mono">
                      {observable.value}
                    </span>

                    <span>
                      {observable.enrichment?.country
                        || '—'}
                    </span>

                    <span className="network-cell">
                      {observable.enrichment ? (
                        <>
                          <strong>
                            {observable.enrichment.asn}
                          </strong>
                          <small>
                            {observable.enrichment.as_name}
                          </small>
                        </>
                      ) : (
                        '—'
                      )}
                    </span>

                    <strong>
                      {observable.related_indicator_count.toLocaleString()}
                    </strong>
                  </button>
                ),
              )}
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


export default Infrastructure