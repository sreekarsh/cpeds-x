/**
 * Authentication context for CPEDS-X.
 *
 * Holds the current user + token, persists the token to localStorage, and
 * exposes login/signup/logout helpers. On mount it restores a saved token and
 * validates it against /auth/me, so a page refresh keeps you signed in.
 */
import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import {
  TOKEN_KEY,
  apiLogin,
  apiSignup,
  apiMe,
  errMessage,
} from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [initializing, setInitializing] = useState(true)

  const applySession = useCallback((token, userObj) => {
    localStorage.setItem(TOKEN_KEY, token)
    setUser(userObj)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    setUser(null)
  }, [])

  // Restore session on first load.
  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY)
    if (!token) {
      setInitializing(false)
      return
    }
    apiMe()
      .then((res) => setUser(res.data))
      .catch(() => localStorage.removeItem(TOKEN_KEY))
      .finally(() => setInitializing(false))
  }, [])

  // React to forced logout from the axios interceptor (expired/invalid token).
  useEffect(() => {
    const onUnauthorized = () => setUser(null)
    window.addEventListener('cpeds-unauthorized', onUnauthorized)
    return () => window.removeEventListener('cpeds-unauthorized', onUnauthorized)
  }, [])

  const login = useCallback(async (email, password) => {
    try {
      const res = await apiLogin(email, password)
      applySession(res.data.access_token, res.data.user)
      return { ok: true }
    } catch (e) {
      return { ok: false, error: errMessage(e, 'Incorrect email or password.') }
    }
  }, [applySession])

  const signup = useCallback(async (fullName, email, password) => {
    try {
      const res = await apiSignup(fullName, email, password)
      applySession(res.data.access_token, res.data.user)
      return { ok: true }
    } catch (e) {
      return { ok: false, error: errMessage(e, 'Could not create your account.') }
    }
  }, [applySession])

  const value = {
    user,
    initializing,
    isAuthenticated: !!user,
    login,
    signup,
    logout,
    applySession, // used by the reset-password flow to sign in directly
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}
