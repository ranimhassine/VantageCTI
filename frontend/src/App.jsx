import { useState } from 'react'

import Layout from './components/Layout'
import Attack from './views/Attack'
import Analytics from './views/Analytics'
import Infrastructure from './views/Infrastructure'
import Investigate from './views/Investigate'
import IOCExplorer from './views/IOCExplorer'
import LiveFeed from './views/LiveFeed'
import Malware from './views/Malware'
import MicrosoftSecurity from './views/MicrosoftSecurity'
import Overview from './views/Overview'
import Sources from './views/Sources'
import Vulnerabilities from './views/Vulnerabilities'

import './App.css'
import './Intelligence.css'


function App() {
  const [view, setView] = useState('overview')
  const [investigationQuery, setInvestigationQuery] = useState('')

  function openInvestigation(value) {
    setInvestigationQuery(value)
    setView('investigate')
  }

  function navigate(nextView) {
    if (nextView !== 'investigate') {
      setInvestigationQuery('')
    }

    setView(nextView)
  }

  function renderView() {
    switch (view) {
      case 'feed':
        return (
          <LiveFeed onInvestigate={openInvestigation} />
        )

      case 'investigate':
        return (
          <Investigate
            initialQuery={investigationQuery}
          />
        )

      case 'ioc':
        return (
          <IOCExplorer
            onInvestigate={openInvestigation}
          />
        )

      case 'malware':
        return (
          <Malware
            onInvestigate={openInvestigation}
          />
        )

      case 'infrastructure':
        return (
          <Infrastructure
            onInvestigate={openInvestigation}
          />
        )

      case 'vulnerabilities':
        return (
          <Vulnerabilities
            onInvestigate={openInvestigation}
          />
        )

      case 'attack':
        return (
          <Attack
            onInvestigate={openInvestigation}
          />
        )

      case 'analytics':
        return (
          <Analytics
            onInvestigate={openInvestigation}
          />
        )

      case 'microsoft':
        return <MicrosoftSecurity />

      case 'sources':
        return <Sources />

      default:
        return (
          <Overview
            onInvestigate={openInvestigation}
          />
        )
    }
  }

  return (
    <Layout
      activeView={view}
      onNavigate={navigate}
    >
      {renderView()}
    </Layout>
  )
}


export default App