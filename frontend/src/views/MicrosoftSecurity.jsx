import {
  BellRing,
  Binary,
  Clipboard,
  DatabaseZap,
  Network,
  Search,
  SearchCode,
  Shield,
  Users,
} from 'lucide-react'
import {
  useMemo,
  useState,
} from 'react'

import '../Workbench.css'


function detectType(value) {
  const query = value.trim()

  if (
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(query)
  ) {
    return 'ip'
  }

  if (/^https?:\/\//i.test(query)) {
    return 'url'
  }

  if (/^[a-f0-9]{32}$/i.test(query)) {
    return 'md5'
  }

  if (/^[a-f0-9]{40}$/i.test(query)) {
    return 'sha1'
  }

  if (/^[a-f0-9]{64}$/i.test(query)) {
    return 'sha256'
  }

  return 'domain'
}


function generateKql(type, query) {
  const escaped =
    query.replace(/"/g, '\\"')

  if (type === 'ip') {
    return `let IOC = "${escaped}";
DeviceNetworkEvents
| where RemoteIP == IOC
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc`
  }

  if (type === 'url') {
    return `let IOC = "${escaped}";
DeviceNetworkEvents
| where RemoteUrl == IOC or RemoteUrl has IOC
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc`
  }

  if (
    type === 'md5'
    || type === 'sha1'
    || type === 'sha256'
  ) {
    return `let IOC = "${escaped}";
DeviceFileEvents
| where SHA256 == IOC or SHA1 == IOC or MD5 == IOC
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5, InitiatingProcessFileName
| order by Timestamp desc`
  }

  return `let IOC = "${escaped}";
DeviceNetworkEvents
| where RemoteUrl has IOC
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc`
}


const capabilities = [
  {
    icon: BellRing,
    title: 'Incidents & alerts',
    text:
      'Correlate external intelligence with Defender XDR security detections.',
  },
  {
    icon: SearchCode,
    title: 'Advanced Hunting',
    text:
      'Pivot IPs, domains, URLs and hashes into tenant hunting queries.',
  },
  {
    icon: Network,
    title: 'Devices',
    text:
      'Identify endpoints associated with investigated intelligence.',
  },
  {
    icon: Users,
    title: 'Users & entities',
    text:
      'Add organizational entity context to threat investigations.',
  },
  {
    icon: DatabaseZap,
    title: 'Sentinel TI',
    text:
      'Prepare threat intelligence for Sentinel interoperability.',
  },
  {
    icon: Binary,
    title: 'IOC operationalization',
    text:
      'Bridge normalized intelligence with security operations workflows.',
  },
]


function MicrosoftSecurity() {
  const [query, setQuery] =
    useState('176.65.134.121')

  const [huntValue, setHuntValue] =
    useState('176.65.134.121')

  const [copied, setCopied] =
    useState(false)

  const detectedType =
    useMemo(
      () => detectType(huntValue),
      [huntValue],
    )

  const kql =
    useMemo(
      () => generateKql(
        detectedType,
        huntValue,
      ),
      [detectedType, huntValue],
    )


  function generate(event) {
    event.preventDefault()

    if (query.trim()) {
      setHuntValue(query.trim())
    }
  }


  async function copy() {
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
    <div className="workbench-page">
      <header className="page-header">
        <div>
          <span className="eyebrow">
            ORGANIZATIONAL SECURITY CONTEXT
          </span>

          <h1>Microsoft Security</h1>

          <p>
            Connect external threat intelligence with
            Microsoft Defender XDR hunting, detections,
            entities and Sentinel workflows.
          </p>
        </div>

        <span className="connection-state">
          <span />
          NOT CONNECTED
        </span>
      </header>

      <section className="wb-panel" style={{ marginTop: 22 }}>
        <div className="wb-panel-heading">
          <div>
            <h3>Integration status</h3>
            <p>
              Microsoft tenant data remains separate
              from public threat intelligence until an
              authorized connection is configured.
            </p>
          </div>

          <div className="wb-panel-icon">
            <Shield size={18} />
          </div>
        </div>

        <div className="ms-connection-grid">
          <div className="ms-connection-item">
            <span>External CTI</span>
            <strong style={{ color: '#58d6a3' }}>
              Active
            </strong>
          </div>

          <div className="ms-connection-item">
            <span>Defender XDR</span>
            <strong className="disconnected">
              Not connected
            </strong>
          </div>

          <div className="ms-connection-item">
            <span>Microsoft Sentinel</span>
            <strong className="disconnected">
              Not connected
            </strong>
          </div>

          <div className="ms-connection-item">
            <span>Cross-source correlation</span>
            <strong>CTI ready</strong>
          </div>
        </div>
      </section>

      <div className="ms-workspace-grid">
        <section className="wb-panel">
          <div className="wb-panel-heading">
            <div>
              <h3>Threat Hunting Workspace</h3>

              <p>
                Generate an Advanced Hunting pivot for
                an intelligence observable.
              </p>
            </div>

            <div className="wb-panel-icon">
              <SearchCode size={18} />
            </div>
          </div>

          <form
            className="ms-hunt-form"
            onSubmit={generate}
          >
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
              }}
              placeholder="IP, domain, URL or file hash..."
            />

            <button type="submit">
              <Search size={14} />
              {' '}
              Generate
            </button>
          </form>

          <div className="wb-detail-list">
            <div className="wb-detail-row">
              <span>Detected artifact</span>
              <strong>{detectedType}</strong>
            </div>

            <div className="wb-detail-row">
              <span>Target</span>
              <strong>{huntValue}</strong>
            </div>

            <div className="wb-detail-row">
              <span>Execution</span>
              <strong>
                Query generation only — tenant not connected
              </strong>
            </div>
          </div>

          <div className="wb-kql">
            <pre>{kql}</pre>
          </div>

          <button
            className="wb-copy"
            onClick={copy}
          >
            <Clipboard size={14} />
            {copied ? 'Copied' : 'Copy KQL'}
          </button>
        </section>

        <section className="wb-panel">
          <div className="wb-panel-heading">
            <div>
              <h3>Tenant Intelligence</h3>

              <p>
                These values become available after
                Defender XDR authentication.
              </p>
            </div>

            <div className="wb-panel-icon">
              <Shield size={18} />
            </div>
          </div>

          <div className="wb-microsoft-metrics">
            <div className="wb-microsoft-metric">
              <span>IOC sightings</span>
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

            <div className="wb-microsoft-metric">
              <span>Affected users</span>
              <strong>—</strong>
            </div>

            <div className="wb-microsoft-metric">
              <span>Last observation</span>
              <strong>—</strong>
            </div>
          </div>

          <div className="wb-microsoft-state" style={{ marginTop: 15 }}>
            <span />
            Authentication required for tenant telemetry
          </div>
        </section>
      </div>

      <section className="wb-panel" style={{ marginTop: 14 }}>
        <div className="wb-panel-heading">
          <div>
            <h3>Security capabilities</h3>

            <p>
              Planned Microsoft security context that
              complements the platform's vendor-neutral
              CTI layer.
            </p>
          </div>
        </div>

        <div className="ms-capabilities">
          {capabilities.map((capability) => {
            const Icon = capability.icon

            return (
              <article
                className="ms-capability"
                key={capability.title}
              >
                <Icon size={18} />

                <strong>
                  {capability.title}
                </strong>

                <p>
                  {capability.text}
                </p>
              </article>
            )
          })}
        </div>
      </section>

      <section className="wb-panel" style={{ marginTop: 14 }}>
        <div className="wb-panel-heading">
          <div>
            <h3>Intelligence-to-operations workflow</h3>

            <p>
              The target operating model for an
              investigated artifact.
            </p>
          </div>
        </div>

        <div className="workflow">
          <div className="workflow-node">
            <Binary size={18} />
            <span>External intelligence</span>
            <strong>IOC / CVE / ATT&CK</strong>
          </div>

          <span className="workflow-arrow">→</span>

          <div className="workflow-node active">
            <SearchCode size={18} />
            <span>CTI workbench</span>
            <strong>Correlate & enrich</strong>
          </div>

          <span className="workflow-arrow">→</span>

          <div className="workflow-node">
            <Shield size={18} />
            <span>Defender XDR</span>
            <strong>Tenant evidence</strong>
          </div>

          <span className="workflow-arrow">→</span>

          <div className="workflow-node">
            <DatabaseZap size={18} />
            <span>Security operations</span>
            <strong>Hunt & operationalize</strong>
          </div>
        </div>
      </section>
    </div>
  )
}


export default MicrosoftSecurity