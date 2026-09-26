import {
  Activity,
  BarChart3,
  Bug,
  ChevronDown,
  Database,
  Fingerprint,
  Globe2,
  Menu,
  Moon,
  Network,
  Radar,
  Search,
  Shield,
  ShieldCheck,
  Sun,
  Swords,
  X,
} from 'lucide-react'
import {
  useEffect,
  useRef,
  useState,
} from 'react'

import '../Shell.css'


const primaryNavigation = [
  {
    id: 'overview',
    label: 'Command Center',
    icon: Activity,
  },
  {
    id: 'feed',
    label: 'Live Feed',
    icon: Radar,
  },
  {
    id: 'investigate',
    label: 'Investigate',
    icon: Search,
  },
]


const navigationGroups = [
  {
    id: 'intelligence',
    label: 'Intelligence',
    items: [
      {
        id: 'ioc',
        label: 'IOC Explorer',
        icon: Fingerprint,
      },
      {
        id: 'malware',
        label: 'Malware',
        icon: Bug,
      },
      {
        id: 'infrastructure',
        label: 'Infrastructure',
        icon: Network,
      },
      {
        id: 'vulnerabilities',
        label: 'Vulnerabilities',
        icon: ShieldCheck,
      },
      {
        id: 'attack',
        label: 'ATT&CK',
        icon: Swords,
      },
      {
        id: 'analytics',
        label: 'Analytics',
        icon: BarChart3,
      },
    ],
  },
  {
    id: 'integrations',
    label: 'Integrations',
    items: [
      {
        id: 'microsoft',
        label: 'Microsoft Security',
        icon: Shield,
      },
      {
        id: 'sources',
        label: 'Sources',
        icon: Database,
      },
    ],
  },
]


const allNavigation = [
  ...primaryNavigation,
  ...navigationGroups.flatMap(
    (group) => group.items,
  ),
]


function VantageLogo() {
  return (
    <svg
      className="vantage-logo"
      viewBox="0 0 48 48"
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id="vantageGradient"
          x1="5"
          y1="4"
          x2="43"
          y2="44"
        >
          <stop
            offset="0%"
            stopColor="#d6c1ff"
          />
          <stop
            offset="48%"
            stopColor="#9b6cff"
          />
          <stop
            offset="100%"
            stopColor="#6f42d9"
          />
        </linearGradient>
      </defs>

      <path
        d="M24 4.5 39.5 13v18L24 43.5 8.5 31V13Z"
        fill="none"
        stroke="url(#vantageGradient)"
        strokeWidth="2"
      />

      <circle
        cx="24"
        cy="24"
        r="12.5"
        fill="none"
        stroke="url(#vantageGradient)"
        strokeWidth="1.5"
        strokeDasharray="3 3"
        opacity=".75"
      />

      <path
        d="M16.5 27.5c0-7.8 3.4-11.7 7.6-11.7 4.5 0 7.5 3.7 7.5 9.1 0 5.2-1.4 8.3-3.6 11"
        fill="none"
        stroke="url(#vantageGradient)"
        strokeWidth="2.2"
        strokeLinecap="round"
      />

      <path
        d="M20.3 30.8c-.5-2.1-.8-4.1-.8-5.9 0-3.5 1.7-5.7 4.5-5.7 2.7 0 4.4 2.2 4.4 5.7 0 4.1-1.1 6.8-2.6 9.3"
        fill="none"
        stroke="url(#vantageGradient)"
        strokeWidth="2"
        strokeLinecap="round"
      />

      <path
        d="M23.2 32.5c-.5-2.7-.8-5.2-.8-7.4 0-1.5.6-2.4 1.7-2.4 1 0 1.7.9 1.7 2.4 0 2.8-.4 5.4-1.2 8.1"
        fill="none"
        stroke="url(#vantageGradient)"
        strokeWidth="1.8"
        strokeLinecap="round"
      />

      <circle
        cx="24"
        cy="24"
        r="2"
        fill="#b794ff"
      />

      <circle
        cx="24"
        cy="8.5"
        r="1.4"
        fill="#58d6a3"
      />

      <circle
        cx="38"
        cy="30"
        r="1.4"
        fill="#9b6cff"
      />

      <circle
        cx="10"
        cy="30"
        r="1.4"
        fill="#9b6cff"
      />
    </svg>
  )
}


function findView(viewId) {
  return (
    allNavigation.find(
      (item) => item.id === viewId,
    )
    || primaryNavigation[0]
  )
}


function Layout({
  activeView,
  onNavigate,
  children,
}) {
  const [theme, setTheme] = useState(() => {
    const stored =
      window.localStorage.getItem(
        'vantage-theme',
      )

    return (
      stored === 'light'
      || stored === 'dark'
    )
      ? stored
      : 'dark'
  })

  const [openMenu, setOpenMenu] =
    useState(null)

  const [mobileOpen, setMobileOpen] =
    useState(false)

  const navigationRef = useRef(null)

  const currentView =
    findView(activeView)


  useEffect(() => {
    document.documentElement.dataset.theme =
      theme

    window.localStorage.setItem(
      'vantage-theme',
      theme,
    )
  }, [theme])


  useEffect(() => {
    function closeMenus(event) {
      if (
        navigationRef.current
        && !navigationRef.current.contains(
          event.target,
        )
      ) {
        setOpenMenu(null)
      }
    }

    document.addEventListener(
      'mousedown',
      closeMenus,
    )

    return () => {
      document.removeEventListener(
        'mousedown',
        closeMenus,
      )
    }
  }, [])


  function navigate(view) {
    onNavigate(view)
    setOpenMenu(null)
    setMobileOpen(false)
  }


  function toggleTheme() {
    setTheme((current) => (
      current === 'dark'
        ? 'light'
        : 'dark'
    ))
  }


  return (
    <div className="app-shell top-shell">
      <header className="top-navigation">
        <div className="top-navigation-inner">
          <button
            className="top-brand"
            onClick={() => navigate('overview')}
            type="button"
          >
            <span className="top-brand-mark">
              <VantageLogo />
            </span>

            <span className="top-brand-copy">
              <strong>
                VANTAGE CTI
              </strong>

              <small>
                THREAT INTELLIGENCE PLATFORM
              </small>
            </span>
          </button>

          <nav
            className="desktop-navigation"
            ref={navigationRef}
          >
            {primaryNavigation.map(
              (item) => {
                const Icon = item.icon

                return (
                  <button
                    className={
                      `nav-direct ${
                        activeView === item.id
                          ? 'active'
                          : ''
                      }`
                    }
                    key={item.id}
                    onClick={() => (
                      navigate(item.id)
                    )}
                    type="button"
                  >
                    <Icon size={15} />
                    {item.label}
                  </button>
                )
              },
            )}

            {navigationGroups.map(
              (group) => {
                const active =
                  group.items.some(
                    (item) => (
                      item.id === activeView
                    ),
                  )

                return (
                  <div
                    className="nav-group"
                    key={group.id}
                  >
                    <button
                      className={
                        `nav-group-trigger ${
                          active
                            ? 'active'
                            : ''
                        }`
                      }
                      onClick={() => (
                        setOpenMenu(
                          (current) => (
                            current
                            === group.id
                              ? null
                              : group.id
                          ),
                        )
                      )}
                      type="button"
                    >
                      {group.label}

                      <ChevronDown
                        className={
                          openMenu
                          === group.id
                            ? 'rotated'
                            : ''
                        }
                        size={14}
                      />
                    </button>

                    {openMenu === group.id && (
                      <div className="nav-dropdown">
                        <div className="nav-dropdown-label">
                          {group.label}
                        </div>

                        {group.items.map(
                          (item) => {
                            const Icon =
                              item.icon

                            return (
                              <button
                                className={
                                  `nav-dropdown-item ${
                                    activeView
                                    === item.id
                                      ? 'active'
                                      : ''
                                  }`
                                }
                                key={item.id}
                                onClick={() => (
                                  navigate(
                                    item.id,
                                  )
                                )}
                                type="button"
                              >
                                <span className="nav-dropdown-icon">
                                  <Icon size={17} />
                                </span>

                                {item.label}
                              </button>
                            )
                          },
                        )}
                      </div>
                    )}
                  </div>
                )
              },
            )}
          </nav>

          <div className="top-actions">
            <div className="source-health">
              <span className="source-health-dot" />
              4 sources active
            </div>

            <button
              aria-label="Toggle theme"
              className="theme-toggle"
              onClick={toggleTheme}
              title={
                theme === 'dark'
                  ? 'Light mode'
                  : 'Dark mode'
              }
              type="button"
            >
              {theme === 'dark' ? (
                <Sun size={17} />
              ) : (
                <Moon size={17} />
              )}
            </button>

            <button
              aria-label="Open navigation"
              className="mobile-menu-button"
              onClick={() => (
                setMobileOpen(
                  (current) => !current,
                )
              )}
              type="button"
            >
              {mobileOpen ? (
                <X size={20} />
              ) : (
                <Menu size={20} />
              )}
            </button>
          </div>
        </div>

        {mobileOpen && (
          <div className="mobile-navigation">
            <div className="mobile-navigation-group">
              <span>Operations</span>

              <div>
                {primaryNavigation.map(
                  (item) => {
                    const Icon = item.icon

                    return (
                      <button
                        className={
                          activeView
                          === item.id
                            ? 'active'
                            : ''
                        }
                        key={item.id}
                        onClick={() => (
                          navigate(item.id)
                        )}
                        type="button"
                      >
                        <Icon size={16} />
                        {item.label}
                      </button>
                    )
                  },
                )}
              </div>
            </div>

            {navigationGroups.map(
              (group) => (
                <div
                  className="mobile-navigation-group"
                  key={group.id}
                >
                  <span>{group.label}</span>

                  <div>
                    {group.items.map(
                      (item) => {
                        const Icon =
                          item.icon

                        return (
                          <button
                            className={
                              activeView
                              === item.id
                                ? 'active'
                                : ''
                            }
                            key={item.id}
                            onClick={() => (
                              navigate(
                                item.id,
                              )
                            )}
                            type="button"
                          >
                            <Icon size={16} />
                            {item.label}
                          </button>
                        )
                      },
                    )}
                  </div>
                </div>
              ),
            )}
          </div>
        )}
      </header>

      <div className="context-bar">
        <div className="context-bar-inner">
          <div className="context-location">
            <currentView.icon size={15} />
            <span>
              {currentView.label}
            </span>
          </div>

          <div className="context-sources">
            <span><i /> CISA KEV</span>
            <span><i /> URLhaus</span>
            <span><i /> MITRE ATT&CK</span>
            <span><i /> IPinfo</span>
          </div>
        </div>
      </div>

      <main className="workspace top-workspace">
        {children}
      </main>

      <footer className="application-footer">
        <div>
          <VantageLogo />

          <strong>
            VANTAGE CTI
          </strong>

          <span>
            Vendor-neutral threat intelligence
          </span>
        </div>

        <div>
          <Globe2 size={14} />
          CISA KEV · URLhaus · MITRE ATT&CK · IPinfo
        </div>
      </footer>
    </div>
  )
}


export default Layout