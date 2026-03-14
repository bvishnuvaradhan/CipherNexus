import { createContext, useContext, useState, useCallback } from 'react'
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || '/api'
const HackerAuthContext = createContext(null)

export function HackerAuthProvider({ children }) {
  const [hacker, setHacker] = useState(() => {
    const token = sessionStorage.getItem('hacker_token')
    const username = sessionStorage.getItem('hacker_username')
    return token ? { token, username } : null
  })

  const hackerLogin = useCallback(async (username, password) => {
    const res = await axios.post(`${BASE_URL}/auth/hacker-login`, { username, password })
    const { access_token, username: uname } = res.data
    sessionStorage.setItem('hacker_token', access_token)
    sessionStorage.setItem('hacker_username', uname)
    setHacker({ token: access_token, username: uname })
    return uname
  }, [])

  const hackerLogout = useCallback(() => {
    sessionStorage.removeItem('hacker_token')
    sessionStorage.removeItem('hacker_username')
    setHacker(null)
  }, [])

  return (
    <HackerAuthContext.Provider value={{ hacker, hackerLogin, hackerLogout, isAuthenticated: !!hacker }}>
      {children}
    </HackerAuthContext.Provider>
  )
}

export const useHackerAuth = () => useContext(HackerAuthContext)
