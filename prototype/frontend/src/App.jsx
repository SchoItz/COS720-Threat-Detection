import { Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import HomePage from './pages/HomePage'
import ResultPage from './pages/ResultPage'
import UserDetailPage from './pages/UserDetailPage'
import TrainModelPage from './pages/TrainModelPage'

export default function App() {
  return (
    <div className="app">
      <Navbar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/result" element={<ResultPage />} />
          <Route path="/result/user" element={<UserDetailPage />} />
          <Route path="/train" element={<TrainModelPage />} />
        </Routes>
      </main>
    </div>
  )
}
