import {
  ExternalLink,
  Search,
  Swords,
} from 'lucide-react'
import { useEffect, useState } from 'react'

import Pagination from '../components/Pagination'


const API = '/api/v1'
const LIMIT = 25


function Attack({ onInvestigate }) {
  const [data, setData] = useState(null)
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [tactic, setTactic] = useState('')
  const [platform, setPlatform] = useState('')
  const [subtechnique, setSubtechnique] = useState('')
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
        if (tactic) params.set('tactic', tactic)
        if (platform) params.set('platform', platform)

        if (subtechnique) {
          params.set(
            'is_subtechnique',
            subtechnique,
          )
        }

        const response = await fetch(
          `${API}/attack/techniques?${params}`,
          {
            signal: controller.signal,
          },
        )

        if (!response.ok) {
          throw new Error(
            'Unable to load ATT&CK knowledge.',
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
    tactic,
    platform,
    subtechnique,
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
            ADVERSARY KNOWLEDGE
          </span>

          <h1>MITRE ATT&CK</h1>

          <p>
            Explore active Enterprise techniques and
            sub-techniques in the local knowledge base.
          </p>
        </div>

        <div className="header-symbol">
          <Swords size={21} />
        </div>
      </header>

      <section className="toolbar">
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
            placeholder="Search technique ID, name or description..."
          />
        </label>

        <div className="filters">
          <input
            className="filter-input"
            value={tactic}
            onChange={(event) => {
              update(
                setTactic,
                event.target.value,
              )
            }}
            placeholder="Tactic"
          />

          <input
            className="filter-input"
            value={platform}
            onChange={(event) => {
              update(
                setPlatform,
                event.target.value,
              )
            }}
            placeholder="Platform"
          />

          <select
            value={subtechnique}
            onChange={(event) => {
              update(
                setSubtechnique,
                event.target.value,
              )
            }}
          >
            <option value="">All techniques</option>
            <option value="false">
              Top-level only
            </option>
            <option value="true">
              Sub-techniques only
            </option>
          </select>
        </div>
      </section>

      <section className="panel browser-panel">
        <div className="browser-summary">
          <div>
            <strong>
              {data?.total?.toLocaleString() ?? '—'}
            </strong>
            <span>matching active techniques</span>
          </div>
        </div>

        {error && (
          <div className="page-state error-state">
            {error}
          </div>
        )}

        {loading && (
          <div className="page-state">
            Loading ATT&CK knowledge...
          </div>
        )}

        {!loading && data && (
          <>
            <div className="attack-grid">
              {data.techniques.map(
                (technique) => (
                  <article
                    className="attack-card"
                    key={technique.attack_id}
                  >
                    <div className="attack-card-top">
                      <button
                        onClick={() => {
                          onInvestigate(
                            technique.attack_id,
                          )
                        }}
                      >
                        {technique.attack_id}
                      </button>

                      <span className="type-pill">
                        {technique.is_subtechnique
                          ? 'sub-technique'
                          : 'technique'}
                      </span>
                    </div>

                    <h3>{technique.name}</h3>

                    <p>
                      {technique.description}
                    </p>

                    <div className="tag-list">
                      {technique.tactics?.map(
                        (item) => (
                          <span
                            className="tag"
                            key={item}
                          >
                            {item}
                          </span>
                        ),
                      )}
                    </div>

                    <div className="attack-footer">
                      <span>
                        {technique.platforms
                          ?.slice(0, 3)
                          .join(' · ')}
                      </span>

                      {technique.source_reference && (
                        <a
                          href={
                            technique.source_reference
                          }
                          target="_blank"
                          rel="noreferrer"
                        >
                          <ExternalLink size={14} />
                        </a>
                      )}
                    </div>
                  </article>
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


export default Attack