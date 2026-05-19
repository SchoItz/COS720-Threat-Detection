import { NavLink } from 'react-router-dom'

export default function Navbar() {
  return (
    <nav className="navbar">
      <NavLink to="/" className="navbar-brand">
        <div>
          <div className="navbar-title">AI-Powered Insider Threat Detection System</div>
          <div className="navbar-subtitle">COS720 – Insider Threat Detection</div>
        </div>
      </NavLink>

      <div className="navbar-links">
        <NavLink
          to="/"
          end
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          Analyse
        </NavLink>
        <NavLink
          to="/train"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          Train Model
        </NavLink>
      </div>
    </nav>
  )
}
