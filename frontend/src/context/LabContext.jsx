import { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { labsAPI } from '../services/api'

const LabContext = createContext(null)

export function LabProvider({ children }) {
  const [activeLab, setActiveLab] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchActiveLab = useCallback(async () => {
    try {
      const res = await labsAPI.getActive()
      setActiveLab(res.data.lab || null)
    } catch {
      setActiveLab(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchActiveLab() }, [fetchActiveLab])

  const createLab = useCallback(async (name, description) => {
    const res = await labsAPI.create({ name, description })
    setActiveLab(res.data.lab)
    return res.data.lab
  }, [])

  const destroyLab = useCallback(async (labId) => {
    await labsAPI.destroy(labId)
    setActiveLab(null)
  }, [])

  return (
    <LabContext.Provider value={{ activeLab, loading, createLab, destroyLab, refresh: fetchActiveLab }}>
      {children}
    </LabContext.Provider>
  )
}

export const useLab = () => useContext(LabContext)
