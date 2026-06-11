import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Incidents from './pages/Incidents'
import Sante from './pages/Sante'

export default function App() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-6 overflow-auto">
        <Routes>
          <Route path="/"          element={<Dashboard />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/sante"     element={<Sante />}    />
        </Routes>
      </main>
    </div>
  )
}