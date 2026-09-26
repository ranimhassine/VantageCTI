import {
  ExternalLink,
  Globe2,
  Network,
  Shield,
} from 'lucide-react'


function formatTimestamp(value) {
  if (!value) {
    return 'Unknown'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return String(value)
  }

  return new Intl.DateTimeFormat(
    'en',
    {
      dateStyle: 'medium',
      timeStyle: 'short',
    },
  ).format(date)
}


function Field({
  label,
  value,
  mono = false,
}) {
  return (
    <div className="detail-field">
      <span>{label}</span>
      <strong className={mono ? 'mono' : ''}>
        {value || '—'}
      </strong>
    </div>
  )
}


function InvestigationResult({ data }) {
  if (!data) {
    return null
  }

  if (!data.found) {
    return (
      <div className="investigation-empty">
        <Shield size={30} />

        <h3>No local intelligence match</h3>

        <p>
          The value was recognized as
          {' '}
          <strong>
            {data.detected_type.replaceAll('_', ' ')}
          </strong>
          , but it is not currently present in the
          collected intelligence dataset.
        </p>
      </div>
    )
  }

  const results = data.results
  const observable = results.observables?.[0]
  const indicator = results.indicators?.[0]
  const vulnerability = results.vulnerability
  const technique = results.attack_technique

  return (
    <div className="investigation-detail">
      <div className="investigation-heading">
        <div>
          <span className="type-pill">
            {data.detected_type.replaceAll('_', ' ')}
          </span>

          <h2>{data.query}</h2>
        </div>

        <span className="match-badge">
          {data.result_count} local match
          {data.result_count === 1 ? '' : 'es'}
        </span>
      </div>

      {observable && (
        <>
          <div className="detail-grid">
            <Field
              label="Type"
              value={observable.type}
            />

            <Field
              label="Related indicators"
              value={observable.related_indicator_count?.toLocaleString()}
            />

            <Field
              label="First observed"
              value={formatTimestamp(
                observable.first_seen,
              )}
            />

            <Field
              label="Last observed"
              value={formatTimestamp(
                observable.last_seen,
              )}
            />
          </div>

          {observable.enrichments?.map(
            (enrichment) => (
              <section
                className="detail-section"
                key={enrichment.provider}
              >
                <div className="section-title">
                  <Globe2 size={16} />
                  Infrastructure enrichment
                </div>

                <div className="detail-grid">
                  <Field
                    label="Provider"
                    value={enrichment.provider}
                  />

                  <Field
                    label="ASN"
                    value={enrichment.asn}
                    mono
                  />

                  <Field
                    label="Network"
                    value={enrichment.as_name}
                  />

                  <Field
                    label="Network domain"
                    value={enrichment.as_domain}
                    mono
                  />

                  <Field
                    label="Country"
                    value={enrichment.country}
                  />

                  <Field
                    label="Country code"
                    value={enrichment.country_code}
                  />

                  <Field
                    label="Continent"
                    value={enrichment.continent}
                  />

                  <Field
                    label="Retrieved"
                    value={formatTimestamp(
                      enrichment.retrieved_at,
                    )}
                  />
                </div>

                <p className="context-note">
                  Infrastructure metadata provides
                  attribution context. It does not by
                  itself establish maliciousness of a
                  network or country.
                </p>
              </section>
            ),
          )}
        </>
      )}

      {indicator && (
        <>
          <div className="detail-grid">
            <Field
              label="Source"
              value={indicator.source}
            />

            <Field
              label="Status"
              value={indicator.status}
            />

            <Field
              label="Threat type"
              value={indicator.threat_type}
            />

            <Field
              label="First observed"
              value={formatTimestamp(
                indicator.first_seen,
              )}
            />
          </div>

          <section className="detail-section">
            <div className="section-title">
              <Network size={16} />
              Source intelligence
            </div>

            <Field
              label="Indicator"
              value={indicator.value}
              mono
            />

            <div className="tag-list">
              {indicator.tags?.map((tag) => (
                <span
                  className="tag"
                  key={tag}
                >
                  {tag}
                </span>
              ))}
            </div>

            {indicator.source_reference && (
              <a
                className="external-button"
                href={indicator.source_reference}
                target="_blank"
                rel="noreferrer"
              >
                Source reference
                <ExternalLink size={14} />
              </a>
            )}
          </section>
        </>
      )}

      {vulnerability && (
        <>
          <div className="detail-grid">
            <Field
              label="CVE"
              value={vulnerability.cve_id}
              mono
            />

            <Field
              label="Vendor"
              value={vulnerability.vendor}
            />

            <Field
              label="Product"
              value={vulnerability.product}
            />

            <Field
              label="Added to KEV"
              value={vulnerability.date_added}
            />
          </div>

          <section className="detail-section">
            <div className="section-title">
              <Shield size={16} />
              Known exploited vulnerability
            </div>

            <h3>{vulnerability.name}</h3>

            <p className="description-text">
              {vulnerability.description}
            </p>
          </section>
        </>
      )}

      {technique && (
        <>
          <div className="detail-grid">
            <Field
              label="ATT&CK ID"
              value={technique.attack_id}
              mono
            />

            <Field
              label="Technique"
              value={technique.name}
            />

            <Field
              label="Type"
              value={
                technique.is_subtechnique
                  ? 'Sub-technique'
                  : 'Technique'
              }
            />

            <Field
              label="Source"
              value={technique.source}
            />
          </div>

          <section className="detail-section">
            <div className="section-title">
              <Shield size={16} />
              ATT&CK context
            </div>

            <div className="tag-list">
              {technique.tactics?.map((tactic) => (
                <span
                  className="tag"
                  key={tactic}
                >
                  {tactic}
                </span>
              ))}
            </div>

            <p className="description-text">
              {technique.description}
            </p>

            {technique.source_reference && (
              <a
                className="external-button"
                href={technique.source_reference}
                target="_blank"
                rel="noreferrer"
              >
                MITRE ATT&CK reference
                <ExternalLink size={14} />
              </a>
            )}
          </section>
        </>
      )}
    </div>
  )
}


export default InvestigationResult