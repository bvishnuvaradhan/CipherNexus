import { createContext, useContext, useState, useCallback } from 'react'
import { authAPI } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const token = localStorage.getItem('access_token')
    const username = localStorage.getItem('username')
    return token ? { token, username } : null
  })

  const login = useCallback(async (username, password) => {
    const res = await authAPI.login({ username, password })
    const { access_token, username: uname } = res.data
    localStorage.setItem('access_token', access_token)
    localStorage.setItem('username', uname)
    setUser({ token: access_token, username: uname })
    return uname
  }, [])

  const logout = useCallback(async () => {
    try { await authAPI.logout() } catch (_) {}
    localStorage.removeItem('access_token')
    localStorage.removeItem('username')
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
