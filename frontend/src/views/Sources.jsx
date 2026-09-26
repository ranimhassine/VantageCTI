import {
  Database,
  Fingerprint,
  Globe2,
  Radar,
  ShieldAlert,
  Swords,
} from 'lucide-react'
import { useEffect, useState } from 'react'


const API = '/api/v1'


function SourceCard({
  icon: Icon,
  name,
  role,
  records,
  status = 'Active',
  children,
}) {
  return (
    <article className="integration-card">
      <div className="integration-card-header">
        <div className="integration-icon">
          <Icon size={20} />
        </div>

        <div>
          <h2>{name}</h2>
          <p>{role}</p>
        </div>

        <span className="integration-status connected">
          {status}
        </span>
      </div>

      <div className="source-record-count">
        <span>Available records</span>
        <strong>
          {records === undefined
            ? '—'
            : records.toLocaleString()}
        </strong>
      </div>

      {children}
    </article>
  )
}


function Sources() {
  const [summary, setSummary] = useState(null)
  const [error, setError] = useState('')


  useEffect(() => {
    async function load() {
      try {
        const response = await fetch(
          `${API}/dashboard/summary`,
        )

        if (!response.ok) {
          throw new Error(
            'Unable to load source statistics.',
          )
        }

        setSummary(await response.json())
      } catch (loadError) {
        setError(loadError.message)
      }
    }

    load()
  }, [])


  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">
            COLLECTION & ENRICHMENT
          </span>

          <h1>Intelligence Sources</h1>

          <p>
            Understand where platform intelligence
            originates and how each source contributes.
          </p>
        </div>

        <div className="header-symbol">
          <Database size={21} />
        </div>
      </header>

      {error && (
        <div className="page-state error-state">
          {error}
        </div>
      )}

      <div className="source-overview-grid">
        <SourceCard
          icon={ShieldAlert}
          name="CISA KEV"
          role="Known exploited vulnerabilities"
          records={summary?.vulnerabilities}
        >
          <p>
            Provides vulnerability intelligence for
            CVEs known to have been exploited in the
            wild.
          </p>

          <div className="capability-list">
            <span>CVE identification</span>
            <span>Vendor and product context</span>
            <span>Catalog inclusion date</span>
          </div>
        </SourceCard>

        <SourceCard
          icon={Radar}
          name="URLhaus"
          role="Malicious URL intelligence"
          records={summary?.indicators}
        >
          <p>
            Supplies collected malicious URL records,
            source tags, status and malware context.
          </p>

          <div className="capability-list">
            <span>Malicious URLs</span>
            <span>Online/offline state</span>
            <span>Malware and source tags</span>
          </div>
        </SourceCard>

        <SourceCard
          icon={Swords}
          name="MITRE ATT&CK"
          role="Adversary behavior knowledge"
          records={summary?.active_attack_techniques}
        >
          <p>
            Provides Enterprise ATT&CK techniques,
            sub-techniques, tactics and platforms.
          </p>

          <div className="capability-list">
            <span>Techniques</span>
            <span>Sub-techniques</span>
            <span>Tactics and platforms</span>
          </div>
        </SourceCard>

        <SourceCard
          icon={Globe2}
          name="IPinfo"
          role="Infrastructure enrichment"
          records={summary?.enriched_ips}
        >
          <p>
            Enriches IP observables with network,
            ASN, country and regional context.
          </p>

          <div className="capability-list">
            <span>ASN attribution</span>
            <span>Network metadata</span>
            <span>Geographic context</span>
          </div>
        </SourceCard>
      </div>

      <section className="panel source-principle">
        <Fingerprint size={22} />

        <div>
          <h2>Normalized intelligence layer</h2>

          <p>
            Source data is collected into a common
            platform model so analysts can pivot
            between indicators, observables,
            vulnerabilities, infrastructure and
            adversary knowledge without working
            directly against individual feeds.
          </p>
        </div>
      </section>
    </>
  )
}


export default Sources